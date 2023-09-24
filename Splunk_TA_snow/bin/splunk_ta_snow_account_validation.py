#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import base64
import copy
import json
import re
import traceback

import framework.log as log
import requests
import splunk.admin as admin
from framework import rest, utils
from snow import proxy_port_value_validation
from solnlib import conf_manager
from splunktaucclib.rest_handler.endpoint.validator import Validator

APP_NAME = "Splunk_TA_snow"
_LOGGER = log.Logs().get_logger("main")


class GetSessionKey(admin.MConfigHandler):
    def __init__(self):
        self.session_key = self.getSessionKey()


class URLValidation(Validator):
    """
    Validate ServiceNow URL
    """

    def __init__(self, *args, **kwargs):
        super(URLValidation, self).__init__(*args, **kwargs)

    def validate(self, value, data):

        url = data["url"]
        _LOGGER.info("Verifying URL for ServiceNow instance {}.".format(url))

        url_pattern = r"^(https:\/\/)[^\/]+\/?$"
        if re.match(url_pattern, url):
            _LOGGER.info("Entered URL for ServiceNow instance {} is valid.".format(url))
            return True

        else:
            msg = "Invalid URL {} provided. Please provide URL in this format: https://myaccount.service-now.com".format(  # noqa : E501
                url
            )
            _LOGGER.error(
                "Invalid URL {} provided. Please provide URL in this format: https://myaccount.service-now.com".format(
                    url
                )
            )
            self.put_msg(msg, True)
            return False


class AccountValidation(Validator):
    """
    Validate ServiceNow account details
    """

    def __init__(self, *args, **kwargs):
        super(AccountValidation, self).__init__(*args, **kwargs)

    def getProxySettings(self, defaults):
        # Obtain proxy settings, if proxy has been configured, by reading splunk_ta_snow_settings.conf
        session_key_obj = GetSessionKey()
        session_key = session_key_obj.session_key

        settings_cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-splunk_ta_snow_settings".format(
                APP_NAME
            ),
        )

        splunk_ta_snow_settings_conf = settings_cfm.get_conf(
            "splunk_ta_snow_settings"
        ).get_all()

        for key, value in splunk_ta_snow_settings_conf["proxy"].items():
            defaults[key] = value

        return defaults

    def validate(self, value, data):
        _LOGGER.info(
            "Verifying username and password for ServiceNow instance {}.".format(
                data["url"]
            )
        )
        defaults = self.getProxySettings(copy.deepcopy(data))
        if (
            utils.is_true(defaults.get("proxy_enabled") or "0")
            and "proxy_port" in defaults
            and not proxy_port_value_validation(defaults["proxy_port"])
        ):
            self.put_msg(
                "Invalid Proxy Port value in Configuration file,Proxy Port "
                "should be within the range of [1 and 65535]",
                True,
            )
            return False

        url = defaults["url"]

        data = empty_values(data)
        if not data:
            return False
        if data.get("auth_type", "") == "oauth":
            # exiting for oauth auth_type as its account validation is already done in JS.
            return True

        # Validate username and password for the account url entered
        uri = (
            "{}/incident.do?JSONv2&sysparm_query="
            "sys_updated_on>=2000-01-01+00:00:00&sysparm_record_count=1"
        )
        url = uri.format(url)
        proxy_info = rest.build_proxy_info(defaults)
        session_key = GetSessionKey().session_key
        sslconfig = utils.get_sslconfig(defaults, session_key, _LOGGER)
        try:
            credentials = base64.urlsafe_b64encode(
                ("%s:%s" % (defaults["username"], defaults["password"])).encode("UTF-8")
            ).decode("ascii")
            headers = {"Authorization": "Basic %s" % credentials}
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
        except requests.exceptions.ProxyError as e:
            msg = "Unable to connect to Proxy. For more details, please check the splunk_ta_snow_main.log file."
            _LOGGER.error("Unable to connect to Proxy. Error occured: {}".format(e))
            self.put_msg(msg, True)
            return False
        except Exception:
            msg = "Unable to reach server at {}. Check configurations and network settings.".format(
                defaults["url"]
            )
            _LOGGER.error(
                "Unable to reach ServiceNow instance at {0}. The reason for failure is={1}".format(
                    defaults["url"], traceback.format_exc()
                )
            )

            self.put_msg(msg, True)
            return False
        else:
            if resp.status_code not in (200, 201):
                msg = (
                    "Failed to verify ServiceNow username and password, " "code={} ({})"
                ).format(resp.status_code, resp.reason)
                _LOGGER.error(
                    "Failure occurred while verifying username and password. Response code={} ({})".format(
                        resp.status_code, resp.reason
                    )
                )

                self.put_msg(msg, True)
                return False
            else:
                # This code is developed under ADDON-21364
                try:
                    json.loads(content)
                except ValueError:
                    msg = "Authentication failed. ServiceNow instance is suspended or inactive."
                    _LOGGER.error(
                        "Error Message: {} \nContent : {}".format(msg, content)
                    )
                    self.put_msg(msg, True)
                    return False
                return True


class ProxyValidation(Validator):
    """
    Validate Proxy details provided
    """

    def __init__(self, *args, **kwargs):
        super(ProxyValidation, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        _LOGGER.info("Verifying proxy details")

        username_val = data.get("proxy_username")
        password_val = data.get("proxy_password")

        # If password is specified, then username is required
        if password_val and not username_val:
            self.put_msg(
                "Username is required if password is specified", high_priority=True
            )
            return False
        # If username is specified, then password is required
        elif username_val and not password_val:
            self.put_msg(
                "Password is required if username is specified", high_priority=True
            )
            return False

        # If length of username is not satisfying the String length criteria
        if username_val:
            str_len = len(username_val)
            _min_len = 1
            _max_len = 50
            if str_len < _min_len or str_len > _max_len:
                msg = (
                    "String length of username should be between %(min_len)s and %(max_len)s"
                    % {"min_len": _min_len, "max_len": _max_len}
                )
                self.put_msg(msg, high_priority=True)
                return False

        return True


class RemoveRedundantParam(Validator):
    """
    Validates and removes redundant parameter based on account type selected
    """

    def __init__(self, *args, **kwargs):
        super(RemoveRedundantParam, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        data = empty_values(data)
        return False if not data else True


def empty_values(data_dict):
    """
    Empties the values of keys irrelevant to auth_type selected. Logs an error
    of auth_type provided is invalid.
    """
    if data_dict.get("auth_type", "") == "basic":
        data_dict["endpoint"] = data_dict["refresh_token"] = data_dict[
            "access_token"
        ] = data_dict["client_id"] = data_dict["client_secret"] = ""
    elif data_dict.get("auth_type", "") == "oauth":
        data_dict["password"] = data_dict["username"] = ""
    else:
        _LOGGER.error(
            "Received an invalid Authentication Type: {}. "
            "Please reconfigure the account.".format(
                data_dict.get("auth_type", "<no authentication type found>")
            )
        )
        return False

    return data_dict
