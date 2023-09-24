#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import argparse
import base64
import csv
import gzip
import json
import os.path as op
import re
import sys
import time
import traceback

import framework.log as log
import requests
import snow_consts
import snow_oauth_helper as soauth
import snow_utility as su
import splunk.Intersplunk as si
from framework import rest, utils
from solnlib import conf_manager

utils.remove_http_proxy_env_vars()


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        si.parseError("{0}. {1}".format(message, self.format_usage()))


class ICaseDictReader(csv.DictReader, object):
    @property
    def fieldnames(self):
        return [
            field.strip().lower() for field in super(ICaseDictReader, self).fieldnames
        ]


class SnowTicket(object):
    def __init__(self):
        self.session_key = self._get_session_key()
        self.logger = log.Logs().get_logger(self._get_log_file())
        self.snow_account = self._get_service_now_account()
        loglevel = self.snow_account.get("loglevel", "INFO")
        log.Logs().set_level(loglevel)
        self.subcommand = "create"
        self.sys_id = None

    def _get_session_key(self):
        """
        When called as custom search script, splunkd feeds the following
        to the script as a single line
        'authString:<auth><userId>admin</userId><username>admin</username>\
            <authToken><32_character_long_uuid></authToken></auth>'

        When called as an alert callback script, splunkd feeds the following
        to the script as a single line
        sessionKey=31619c06960f6deaa49c769c9c68ffb6
        """

        import urllib.parse

        session_key = sys.stdin.readline()
        m = re.search("authToken>(.+)</authToken", session_key)
        if m:
            session_key = m.group(1)
        else:
            session_key = session_key.replace("sessionKey=", "").strip()
        session_key = urllib.parse.unquote(session_key.encode("ascii").decode("ascii"))
        session_key = session_key.encode().decode("utf-8")
        return session_key

    def handle(self):
        try:
            self._do_handle()
        except Exception:
            self.logger.error(traceback.format_exc())

    def _do_handle(self):
        self.logger.info("Start of ServiceNow script")

        results = []
        for event in self._get_events():
            if event is None:
                break

            result = self._handle_event(event)
            if result:
                if not result.get("Error Message"):
                    result["_time"] = time.time()
                    results.append(result)
                else:
                    results.append(result)
        si.outputResults(results)

        self.logger.info("End of ServiceNow script")

    def _handle_event(self, event):
        if event.get("scripted_endpoint"):
            endpoint = event["scripted_endpoint"]
            self.scripted_endpoint = event["scripted_endpoint"]
        else:
            endpoint = self._get_endpoint()

        endpoint = "{0}{1}".format(self.snow_account["url"], endpoint.lstrip("/"))

        event_data = self._prepare_data(event)
        if not event_data:
            self.logger.info("No event data is available")
            return
        if event_data.get("Error Message"):
            return event_data

        event_data = json.dumps(event_data)
        headers = {
            "Content-type": "application/json",
            "Accept": "application/json",
        }

        # Adding access_token in the headers if auth_type = oauth
        if self.snow_account["auth_type"] == "oauth":
            headers.update(
                {"Authorization": "Bearer %s" % self.snow_account["access_token"]}
            )
        else:
            credentials = base64.urlsafe_b64encode(
                (
                    f'{self.snow_account["username"]}:{self.snow_account["password"]}'
                ).encode("UTF-8")
            ).decode("ascii")
            headers.update({"Authorization": "Basic %s" % credentials})

        proxy_info = rest.build_proxy_info(self.snow_account)
        self.logger.debug("Sending request to %s: %s", endpoint, event_data)
        for _ in range(3):
            ok, result = self._do_event(
                proxy_info, endpoint, event_data, headers, retry=_
            )
            if ok:
                return result
        return self._get_failure_message()

    def _do_event(self, proxy_info, endpoint, event_data, headers, retry=0):
        # This function will be re-executed if oauth access token will be regenerated
        session_key = self.snow_account["session_key"]
        sslconfig = utils.get_sslconfig(self.snow_account, session_key, self.logger)
        if retry > 0 and self.snow_account["auth_type"] == "oauth":
            self.logger.info("Retry count: {}/3".format(retry + 1))
            headers.update(
                {"Authorization": "Bearer %s" % self.snow_account["access_token"]}
            )
        self.logger.info("Initiating request to {}".format(endpoint))
        try:
            # semgrep ignore reason: we have custom handling for unsuccessful HTTP status codes
            response = requests.request(  # nosemgrep: python.requests.best-practice.use-raise-for-status.use-raise-for-status  # noqa: E501
                self._get_http_method(),
                endpoint,
                data=event_data,
                headers=headers,
                proxies=proxy_info,
                timeout=120,
                verify=sslconfig,
            )
            content = response.content
            self.logger.info(
                "Sending request to %s, get response code %s",
                endpoint,
                response.status_code,
            )
            result = self._handle_response(response, content)
            self.logger.info("Ending request to {}".format(endpoint))
            # Since the access token is updated in the configuration file, we will retry the incident/event creation
            if utils.is_true(result.get("retry", False)):
                return False, result
            return True, result
        except Exception:
            self.logger.error(
                "Failed to connect to %s, error=%s", endpoint, traceback.format_exc()
            )
            self._handle_error()
            return False, None

    def _get_endpoint(self):
        if su.get_selected_api(self.session_key, self.logger) == "import_set_api":
            return f"api/now/import/{self._get_table()}"
        if self.subcommand == "create":
            return f"api/now/table/{self._get_table()}"
        else:
            return f"api/now/table/{self._get_table()}/{self.sys_id}"

    def _get_http_method(self):
        if self.subcommand == "update":
            return "PUT"
        else:
            return "POST"

    def _get_service_now_account(self):
        """
        This function is used read config files
        :return: snow_account dictionary
        """

        snow_account = {
            "session_key": self.session_key,
            "app_name": op.basename(op.dirname(op.dirname(op.abspath(__file__)))),
        }
        account_access_fields = [
            "username",
            "password",
            "client_id",
            "client_secret",
            "access_token",
            "refresh_token",
            "auth_type",
        ]

        try:
            # Read account details from conf file
            account_cfm = conf_manager.ConfManager(
                self.session_key,
                snow_consts.APP_NAME,
                realm="__REST_CREDENTIAL__#{}#configs/conf-splunk_ta_snow_account".format(
                    snow_consts.APP_NAME
                ),
            )
            splunk_ta_snow_account_conf = account_cfm.get_conf(
                "splunk_ta_snow_account"
            ).get_all()
            self.logger.info(
                "Getting details for account '{}'".format(
                    self.account  # pylint: disable=E1101
                )
            )

            # Check if account is empty
            if not self.account:  # pylint: disable=E1101
                si.generateErrorResults("Enter ServiceNow account name.")
                raise Exception(
                    "Account name cannot be empty. Enter a configured account name or "
                    "create new account by going to Configuration page of the Add-on."
                )
            # Get account details
            elif self.account in splunk_ta_snow_account_conf:  # pylint: disable=E1101
                account_details = splunk_ta_snow_account_conf[
                    self.account  # pylint: disable=E1101
                ]

                snow_account["account"] = self.account  # pylint: disable=E1101
                prefix = re.search("^https?://", account_details["url"])
                if not prefix:
                    snow_account["url"] = "https://{}".format(account_details["url"])
                else:
                    snow_account["url"] = account_details["url"]

                if not snow_account["url"].endswith("/"):
                    snow_account["url"] = "{}/".format(snow_account["url"])

                snow_account[
                    "disable_ssl_certificate_validation"
                ] = account_details.get("disable_ssl_certificate_validation", 0)

                account_auth_type = account_details.get("auth_type", "basic")

                if account_auth_type not in ["basic", "oauth"]:
                    si.generateErrorResults(
                        "'{}' is not configured with the desired authentication type. Expected "
                        "values are 'basic' and 'oauth'. Current value is '{}'".format(
                            self.account, account_auth_type  # pylint: disable=E1101
                        )
                    )
                    raise Exception(
                        "'{}' is not configured with the desired authentication type. Expected "
                        "values are 'basic' and 'oauth'. Current value is '{}'".format(
                            self.account, account_auth_type  # pylint: disable=E1101
                        )
                    )

                snow_account["auth_type"] = account_auth_type

                # Collecting details of account
                for field in account_access_fields:
                    if field in account_details.keys():
                        if (
                            field in ["password"]
                            and account_details.get("auth_type", "basic") == "basic"
                        ):
                            snow_account[field] = (
                                account_details[field]
                                .encode("ascii", "replace")
                                .decode("ascii")
                            )
                        elif (
                            field
                            in [
                                "client_id",
                                "client_secret",
                                "access_token",
                                "refresh_token",
                            ]
                            and account_details.get("auth_type", "basic") == "oauth"
                        ):
                            snow_account[field] = (
                                account_details[field]
                                .encode("ascii", "replace")
                                .decode("ascii")
                            )
                        else:
                            snow_account[field] = account_details[field]

            # Invalid account name
            else:
                si.generateErrorResults(
                    "'"
                    + self.account  # pylint: disable=E1101
                    + "' is not configured. Enter a configured account name or create "
                    "new account by going to Configuration page of the Add-on."
                )
                raise Exception(
                    "Entered ServiceNow account name is invalid. Enter a configured account name or "
                    "create new account by going to Configuration page of the Add-on."
                )

            # Read log and proxy setting details from conf file
            setting_cfm = conf_manager.ConfManager(
                self.session_key,
                snow_consts.APP_NAME,
                realm="__REST_CREDENTIAL__#{}#configs/conf-splunk_ta_snow_settings".format(
                    snow_consts.APP_NAME
                ),
            )
            splunk_ta_snow_setting_conf = setting_cfm.get_conf(
                "splunk_ta_snow_settings"
            ).get_all()

            if utils.is_true(
                splunk_ta_snow_setting_conf["proxy"].get("proxy_enabled", False)
            ):
                snow_account["proxy_enabled"] = splunk_ta_snow_setting_conf["proxy"][
                    "proxy_enabled"
                ]
                if splunk_ta_snow_setting_conf["proxy"].get("proxy_port"):
                    snow_account["proxy_port"] = int(
                        splunk_ta_snow_setting_conf["proxy"]["proxy_port"]
                    )
                if splunk_ta_snow_setting_conf["proxy"].get("proxy_url"):
                    snow_account["proxy_url"] = splunk_ta_snow_setting_conf["proxy"][
                        "proxy_url"
                    ]
                if splunk_ta_snow_setting_conf["proxy"].get("proxy_username"):
                    snow_account["proxy_username"] = splunk_ta_snow_setting_conf[
                        "proxy"
                    ]["proxy_username"]
                if splunk_ta_snow_setting_conf["proxy"].get("proxy_password"):
                    snow_account["proxy_password"] = splunk_ta_snow_setting_conf[
                        "proxy"
                    ]["proxy_password"]
                if splunk_ta_snow_setting_conf["proxy"].get("proxy_type"):
                    snow_account["proxy_type"] = splunk_ta_snow_setting_conf["proxy"][
                        "proxy_type"
                    ]
                if splunk_ta_snow_setting_conf["proxy"].get("proxy_rdns"):
                    snow_account["proxy_rdns"] = splunk_ta_snow_setting_conf["proxy"][
                        "proxy_rdns"
                    ]

            if "loglevel" in list(splunk_ta_snow_setting_conf["logging"].keys()):
                snow_account["loglevel"] = splunk_ta_snow_setting_conf["logging"][
                    "loglevel"
                ]

            return snow_account
        except Exception:
            error_msg = str(traceback.format_exc())
            if "splunk_ta_snow_account does not exist." in error_msg:
                si.generateErrorResults(
                    "No ServiceNow account configured. "
                    "Configure account by going to Configuration page of the Add-on."
                )
                self.logger.error(
                    "No ServiceNow account configured. "
                    "Configure account by going to Configuration page of the Add-on.\n"
                    + traceback.format_exc()
                )
            else:
                self.logger.error(traceback.format_exc())

    def _prepare_data(self, event):
        """
        Return a dict like object
        """
        return event

    def _get_events(self):
        """
        Return events that need to be handled
        """
        raise NotImplementedError("Derive class shall implement this method.")

    def _get_log_file(self):
        """
        Return the log file name
        """
        return "ticket"

    def _handle_response(self, response, content):
        if response.status_code in (200, 201):
            resp = self._get_resp_record(content)
            if resp:
                result = self._get_result(resp)
            else:
                result = {"error": "Failed to create ticket"}
            return result
        else:
            # For response code 400 log message specifying reasons of possible failures.
            if response.status_code == 400:
                self.logger.error(
                    "Failed to create ticket. Return code is {0} ({1}). One of the possible causes of "
                    "failure is absence of event management plugin or Splunk Integration plugin on the "
                    "ServiceNow instance. To fix the issue install the plugin(s) on ServiceNow "
                    "instance.".format(response.status_code, response.reason)
                )

                si.parseError(
                    "Failed to create ticket. Return code is {0} ({1}). One of the possible causes of failure"
                    " is absence of event management plugin or Splunk Integration plugin on the ServiceNow "
                    "instance. To fix the issue install the plugin(s) on ServiceNow "
                    "instance.".format(response.status_code, response.reason)
                )

            # If HTTP status = 401 and auth_type = oauth, there is a possibility that access token is expired
            elif (
                response.status_code == 401
                and self.snow_account["auth_type"] == "oauth"
            ):
                result = {"retry": False}
                self.logger.error(
                    "Failed to create ticket. Return code is {0} ({1}). Failure potentially caused by "
                    " expired access token. Regenerating access token.".format(
                        response.status_code, response.reason
                    )
                )

                # Generating newer access token
                snow_oauth = soauth.SnowOAuth(self.snow_account, self._get_log_file())
                update_status = snow_oauth.regenerate_oauth_access_tokens()

                # If access token is updated successfully, retry incident/event creation
                if update_status:
                    # Updating the values in self.snow_account variable with the latest tokens
                    self.snow_account = self._get_service_now_account()
                    result = {"retry": True}
                else:
                    self.logger.error(
                        "Unable to regenerate new access token. Failure potentially caused by "
                        "the expired refresh token. To fix the issue, reconfigure the account and try again."
                    )

                    si.parseError(
                        "Failed to create ticket. Return code is {0} ({1}). "
                        "Failed to generate a new access token to resolve the issue. "
                        "Failure potentially caused by the expired refresh token. To fix the issue, reconfigure "
                        "the account and try again.".format(
                            response.status_code, response.reason
                        )
                    )

                return result

            else:
                self.logger.error(
                    "Failed to create ticket. Return code is {0} ({1}).".format(
                        response.status_code, response.reason
                    )
                )
                si.parseError(
                    "Failed to create ticket. Return code is {0} ({1}).".format(
                        response.status_code, response.reason
                    )
                )

        return None

    def _handle_error(self, msg="Failed to create ticket."):
        si.parseError(msg)

    def _get_ticket_link(self, sys_id):
        link = "{0}{1}.do?sysparm_query=sys_id={2}".format(
            self.snow_account["url"], self._get_table(), sys_id
        )
        return link

    def _get_resp_record(self, content):
        resp = json.loads(content)
        if resp.get("error"):
            self.logger.error("Failed with error: %s", resp["error"])
            return None

        if (
            isinstance(resp.get("result"), list)
            and resp.get("result", [{}])[0].get("status", "") == "error"
        ):
            self.logger.error(
                f'Error Message: {resp.get("result")[0].get("error_message")}'
            )
            return {"Error Message": resp.get("result")[0].get("error_message")}
        if isinstance(resp["result"], list):
            return resp["result"][0]
        return resp["result"]

    def _get_result(self, resp):
        """
        Return a dict object
        """
        raise NotImplementedError("Derived class shall overrides this")

    def _get_table(self):
        """
        Return a table name
        """
        raise NotImplementedError("Derived class shall overrides this")

    def _get_failure_message(self):
        """
        Implement this method to get custom error messages
        Return custom error message in dict form {'error': 'error message'}
        """
        return None


def read_alert_results(alert_file, logger):
    logger.info("Reading alert file %s", alert_file)
    if not op.exists(alert_file):
        logger.error(
            "Unable to find the file {}. Contact Splunk administrator for further information.".format(
                alert_file
            )
        )
        yield None
    with gzip.open(alert_file, "rt") as f:
        for event in ICaseDictReader(f, delimiter=","):
            yield event


def get_account(alert_file):
    """
    This function is used to identify account for alert actions
    :param alert_file: file name
    :return: account name
    """
    try:
        logger = log.Logs().get_logger("ticket")
        if not op.exists(alert_file):
            logger.error(
                "Unable to find the file {}. Contact Splunk administrator for further information.".format(
                    alert_file
                )
            )

        with gzip.open(alert_file, "rt") as f:
            for event in ICaseDictReader(f, delimiter=","):
                return event.get("account")
    except Exception:
        logger.error(traceback.format_exc())
