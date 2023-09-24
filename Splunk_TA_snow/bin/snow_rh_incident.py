#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import base64
import json
import os.path as op
import re
import traceback

import framework.log as log
import requests
import snow_oauth_helper as soauth
import splunk.admin
from framework import rest, utils
from solnlib import conf_manager

utils.remove_http_proxy_env_vars()
APP_NAME = op.basename(op.dirname(op.dirname(op.abspath(__file__))))

_LOGGER = log.Logs().get_logger("main")
log_enter_exit = log.log_enter_exit(_LOGGER)


class SnowIncidentHandler(splunk.admin.MConfigHandler):
    @log_enter_exit
    def setup(self):
        self.supportedArgs.addOptArg("correlation_id")
        self.supportedArgs.addOptArg("number")
        self.supportedArgs.addOptArg("sys_id")
        self.supportedArgs.addOptArg("account")

    def get_conf_stanzas(self, conf_name, stanza=None):
        """
        This method returns the configuration stanzas according to the parameters
        passed in clear text form.
        """
        try:
            cfm = conf_manager.ConfManager(
                self.getSessionKey(),
                APP_NAME,
                realm="__REST_CREDENTIAL__#{}#configs/conf-{}".format(
                    APP_NAME, conf_name
                ),
            )
            if stanza:
                return cfm.get_conf(conf_name, refresh=True).get(stanza)
            else:
                return cfm.get_conf(conf_name, refresh=True).get_all()
        except Exception:
            msg = ""
            if conf_name == "splunk_ta_snow_account":
                msg = (
                    "Error while fetching conf: {}. Make sure you have configured "
                    "the account."
                ).format(conf_name)
                _LOGGER.error(msg)
            else:
                msg = "Error while fetching conf: {}. Contact Splunk administrator.".format(
                    conf_name
                )
                _LOGGER.error(msg)
            raise Exception(msg)

    def _get_service_now_account(self, account):
        # Get the required configuration stanzas
        account_conf = self.get_conf_stanzas("splunk_ta_snow_account", account)
        # Handle the condition when account query parameter is not provided
        if not account:
            account_conf = list(account_conf.values())
            # Raise exception in case multiple accounts are configured in absense of account query parameter
            if len(account_conf) != 1:
                raise Exception(
                    "As multiple accounts are configured, account parameter must be specified."
                )
            else:
                # Return the single configured account
                account_conf = account_conf[0]
        settings_conf = self.get_conf_stanzas("splunk_ta_snow_settings")
        service_now_conf = self.get_conf_stanzas("service_now", "snow_default")

        # Set the log level
        loglevel = settings_conf["logging"].get("loglevel", "INFO")
        log.Logs().set_level(loglevel)

        # Update the dictionary of snow account
        snow_account = {"session_key": self.getSessionKey(), "app_name": APP_NAME}
        account_access_fields = [
            "username",
            "password",
            "client_id",
            "client_secret",
            "access_token",
            "refresh_token",
            "auth_type",
        ]

        for stanza in ("logging", "proxy"):
            snow_account.update(settings_conf[stanza])
        snow_account.update(account_conf)
        snow_account.update(service_now_conf)

        # If no authentication type is provide, considering the default authentication for fetching incident details
        # Default auth_type = basic
        snow_account["auth_type"] = snow_account.get("auth_type", "basic")

        if snow_account.get("proxy_port"):
            try:
                snow_account["proxy_port"] = int(snow_account["proxy_port"])
            except Exception:
                raise Exception("The proxy port must be an integer.")

        snow_url = snow_account.get("url")
        # Verifying required parameters for Basic authentication type
        if not snow_url or (
            snow_account["auth_type"] == "basic"
            and (not snow_account.get("username") or not snow_account.get("password"))
        ):
            raise Exception(
                "ServiceNow account has not been setup for 'Basic' authetication type."
            )

        # Verifying required parameters for OAuth authentication type
        if not snow_url or (
            snow_account["auth_type"] == "oauth"
            and (
                not snow_account.get("access_token")
                or not snow_account.get("refresh_token")
                or not snow_account.get("client_id")
                or not snow_account.get("client_secret")
            )
        ):
            raise Exception(
                "ServiceNow account has not been setup for 'OAuth' authetication type."
            )

        prefix = re.search("^https?://", snow_url)
        if not prefix:
            snow_url = "https://%s" % snow_url

        if not snow_url.endswith("/"):
            snow_url = "%s/" % snow_url

        snow_account["url"] = snow_url
        snow_account["account"] = account
        # Collecting details of account
        for field in account_access_fields:
            if field in account_conf.keys():
                if (
                    field in ["password"]
                    and account_conf.get("auth_type", "basic") == "basic"
                ):
                    snow_account[field] = (
                        account_conf[field].encode("ascii", "replace").decode("ascii")
                    )
                elif (
                    field
                    in ["client_id", "client_secret", "access_token", "refresh_token"]
                    and account_conf.get("auth_type", "basic") == "oauth"
                ):
                    snow_account[field] = (
                        account_conf[field].encode("ascii", "replace").decode("ascii")
                    )
                else:
                    snow_account[field] = account_conf[field]

        return snow_account

    def _retrieve_incident(self, snow_account, **kwargs):
        proxy_info = rest.build_proxy_info(snow_account)

        headers = None
        authentication_type = snow_account.get("auth_type", "basic")

        if authentication_type == "basic":
            credentials = base64.urlsafe_b64encode(
                (f'{snow_account["username"]}:{snow_account["password"]}').encode(
                    "UTF-8"
                )
            ).decode("ascii")
            headers = {"Authorization": "Basic %s" % credentials}

        session_key = snow_account["session_key"]
        sslconfig = utils.get_sslconfig(snow_account, session_key, _LOGGER)

        url = self._get_incident_url(snow_account["url"], **kwargs)
        for retry in range(3):
            if retry > 0:
                _LOGGER.info("Retry count: {}/3".format(retry + 1))
            if authentication_type == "oauth":
                headers = {"Authorization": "Bearer %s" % snow_account["access_token"]}

            _LOGGER.info("Initiating request to {}".format(url))
            try:
                # semgrep ignore reason: we have custom handling for unsuccessful HTTP status codes
                resp = requests.request(  # nosemgrep: python.requests.best-practice.use-raise-for-status.use-raise-for-status  # noqa: E501
                    "GET",
                    url,
                    headers=headers,
                    proxies=proxy_info,
                    timeout=120,
                    verify=sslconfig,
                )
                content = resp.content
                _LOGGER.debug("Got response content {} from {}".format(content, url))
                response_as_json = json.loads(content)
            except Exception:
                msg = ("Failed to get incident, " "reason={}").format(
                    traceback.format_exc()
                )
                _LOGGER.error(msg)
                raise Exception(msg)
            else:
                if resp.status_code not in (200, 201):
                    msg = (
                        "Failed to get incident for {} '{}', " "code={}, reason={}"
                    ).format(
                        list(kwargs.keys())[0],
                        list(kwargs.values())[0],
                        resp.status_code,
                        resp.reason,
                    )

                    # If HTTP status = 401 and auth_type = oauth, there is a possibility that access token is expired
                    if resp.status_code == 401 and snow_account["auth_type"] == "oauth":
                        _LOGGER.error(
                            "Failed to get incident for {} '{}'. Return code is {} ({}). "
                            "Failure potentially caused by "
                            "expired access token. Regenerating access token.".format(
                                list(kwargs.keys())[0],
                                list(kwargs.values())[0],
                                resp.status_code,
                                resp.reason,
                            )
                        )

                        # Generating newer access token
                        snow_oauth = soauth.SnowOAuth(snow_account, "main")
                        update_status = snow_oauth.regenerate_oauth_access_tokens()

                        # If access token is updated successfully, retry incident/event creation
                        if update_status:
                            # Updating the values in self.snow_account variable with the latest tokens
                            snow_account = self._get_service_now_account(
                                snow_account["account"]
                            )
                            continue
                        else:
                            _LOGGER.error(
                                "Unable to generate new access token. Failure potentially caused by "
                                "the expired refresh token. To fix the issue, reconfigure the account and try again."
                            )
                            break
                    else:
                        _LOGGER.error(msg)
                        raise Exception(msg)
                else:
                    break

        _LOGGER.info("Ending request to {}".format(url))
        return response_as_json, url

    def _parse_params(self, key):
        values = self.callerArgs.data.get(key)
        if values and isinstance(values, list):
            _LOGGER.info("Received request with {0} '{1}'".format(key, values))
            return {key: values[0]}
        return {}

    @staticmethod
    def _get_incident_url(snow_url, **kwargs):
        return "%sapi/now/table/incident?sysparm_query=%s=%s" % (
            snow_url,
            list(kwargs.keys())[0],
            list(kwargs.values())[0],
        )

    @staticmethod
    def _build_error_response(response, code, error_msg):
        response.append("code", code)
        response.append("message", error_msg)

    @staticmethod
    def _get_ticket_link(snow_account, **kwargs):
        link = "{}incident.do?sysparm_query={}={}".format(
            snow_account["url"], list(kwargs.keys())[0], list(kwargs.values())[0]
        )
        return link

    @log_enter_exit
    def handleList(self, conf_info):
        # Get the account parameter value if provided
        kwargs = {}
        supported_params = ["sys_id", "number", "correlation_id"]
        resp = conf_info["IncidentResult"]

        for key in supported_params:
            value = self._parse_params(key)
            if value:
                # Verifying if the value is not None
                if not value[key]:
                    msg = "Value of '{}' cannot be Null".format(key)
                    _LOGGER.error(msg)
                    self._build_error_response(resp, 400, msg)
                    return
                # Limiting the length of the key to 200 characters
                value[key] = value[key][0:200]
                kwargs.update(value)
                break

        account = (
            self.callerArgs.get("account")[0]
            if self.callerArgs.get("account")
            else None
        )

        try:
            snow_account = self._get_service_now_account(account)
        except Exception as e:
            _LOGGER.error("Failed to get snow account, reason={}".format(str(e)))
            self._build_error_response(
                resp, 400, "Failed to get snow account, " "reason={}".format(str(e))
            )
            return

        if not kwargs:
            _LOGGER.error(
                "None of correlation id, incident number or sys id is passed. Pass at least one parameter value."
            )

        try:
            response_as_json, url = self._retrieve_incident(snow_account, **kwargs)
            _LOGGER.info(
                "Fetched incident content {} from url {}".format(response_as_json, url)
            )
            response_result = response_as_json["result"]
            if not response_result:
                msg = "Failed to fetch incident, reason={}".format("Record not found.")
                _LOGGER.error(msg)
                raise Exception(msg)
            resp.append("number", response_result[0]["number"])
            resp.append("url_json", url)
            resp.append("url", self._get_ticket_link(snow_account, **kwargs))
        except Exception as e:
            if str(e).__contains__("Unable to find the server"):
                self._build_error_response(resp, 404, "Server Unreachable")
            else:
                if kwargs.__len__() > 0:
                    self._build_error_response(resp, 404, "Record not Found!")
                else:
                    self._build_error_response(
                        resp,
                        404,
                        "Please enter Correlation ID or Incident Number or Sys ID",
                    )


@log_enter_exit
def main():
    splunk.admin.init(SnowIncidentHandler, splunk.admin.CONTEXT_NONE)


if __name__ == "__main__":
    main()
