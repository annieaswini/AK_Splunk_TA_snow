#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#


import import_declare_test  # isort: skip # noqa: F401
import sys

import requests

"""
This module is used to get oauth token from auth code
"""

import json
import os.path as op
import urllib.parse as urllib

import splunk.admin as admin
from framework import utils
from solnlib import conf_manager, log
from solnlib.utils import is_true

sys.path.append(op.join(op.dirname(op.abspath(__file__)), "framework"))

log.Logs.set_context()
logger = log.Logs().get_logger("splunk_ta_snow_main")


"""
REST Endpoint of getting token by OAuth2 in Splunk Add-on UI Framework.
"""


class splunk_ta_snow_rh_oauth2_token(admin.MConfigHandler):
    def setup(self):
        """
        Checks which action is getting called and what parameters are required for the request.
        """
        if self.requestedAction == admin.ACTION_EDIT:

            # Add required args in supported args
            for arg in (
                "url",
                "method",
                "grant_type",
                "code",
                "client_id",
                "client_secret",
                "redirect_uri",
            ):
                self.supportedArgs.addReqArg(arg)
        return

    def handleEdit(self, confInfo):
        """
        Get access token from the auth code received
        Keyword arguments:
        confInfo -- To get the 'url', 'method', 'grant_type', 'code',
        'client_id', 'client_secret', 'redirect_uri' as caller args
        Returns the confInfo dict object in response.
        """
        try:
            logger.debug("In OAuth rest handler to get access token")
            # Get args parameters from the request
            url = self.callerArgs.data["url"][0]
            logger.debug("OAUth url %s", url)
            proxy_info = self.getProxyDetails()

            method = self.callerArgs.data["method"][0]
            # Create payload from the arguments received
            payload = {
                "grant_type": self.callerArgs.data["grant_type"][0],
                "code": self.callerArgs.data["code"][0],
                "client_id": self.callerArgs.data["client_id"][0],
                "client_secret": self.callerArgs.data["client_secret"][0],
                "redirect_uri": self.callerArgs.data["redirect_uri"][0],
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            session_key = self.getSessionKey()
            sslconfig = utils.get_sslconfig({}, session_key, logger)

            # Send http request to get the accesstoken
            # semgrep ignore reason: we have custom handling for unsuccessful HTTP status codes
            resp = requests.request(  # nosemgrep: python.requests.best-practice.use-raise-for-status.use-raise-for-status  # noqa: E501
                method,
                url,
                headers=headers,
                data=urllib.urlencode(payload),
                proxies=proxy_info,
                timeout=120,
                verify=sslconfig,
            )
            content = json.loads(resp.content)
            # Check for any errors in response. If no error then add the content values in confInfo
            if resp.status_code == 200:
                for key, val in content.items():  # py2/3
                    confInfo["token"][key] = val
                logger.info(  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure  # noqa: E501
                    "Exiting OAuth rest handler after getting access token with response %s",
                    resp.status_code,
                )
            else:
                # Else add the error message in the confinfo and logs
                confInfo["token"]["error"] = content["error_description"]
                logger.error(
                    "Exiting OAuth rest handler with status code %s. Server responded with %s",
                    resp.status_code,
                    str(confInfo["token"]["error"]),
                )
        except Exception as exc:
            # Fixed `python.lang.best-practice.logging-error-without-handling.logging-error-without-handling`
            logger.warning("Error occurred while getting access token using auth code")
            raise exc

    def getProxyDetails(self):
        """
        Get proxy details stored in settings conf file
        """
        # Create confmanger object for the app with realm
        cfm = conf_manager.ConfManager(
            self.getSessionKey(),
            "Splunk_TA_snow",
            realm="__REST_CREDENTIAL__#Splunk_TA_snow#configs/conf-splunk_ta_snow_settings",
        )
        # Get Conf object of apps settings
        conf = cfm.get_conf("splunk_ta_snow_settings")
        # Get proxy stanza from the settings
        proxy_config = conf.get("proxy", True)
        if not proxy_config or not is_true(proxy_config.get("proxy_enabled")):
            logger.info("Proxy is not enabled")
            return None

        url = proxy_config.get("proxy_url")
        port = proxy_config.get("proxy_port")

        if url or port:
            if not url:
                raise ValueError('Proxy "url" must not be empty')
            if not self.is_valid_port(port):
                raise ValueError('Proxy "port" must be in range [1,65535]: %s' % port)

        user = proxy_config.get("proxy_username")
        password = proxy_config.get("proxy_password")

        if not all((user, password)):
            logger.info("Proxy has no credentials found")
            user, password = None, None

        proxy_type = (proxy_config.get("proxy_type") or "http").lower()
        if proxy_type not in ("http", "socks5"):
            logger.info('Proxy type not found, set to "HTTP"')
            proxy_type = "http"

        rdns = is_true(proxy_config.get("proxy_rdns"))

        # socks5 causes the DNS resolution to happen on the client
        # socks5h causes the DNS resolution to happen on the proxy server
        if rdns and proxy_type == "socks5":
            proxy_type = "socks5h"

        if user and password:
            proxy_info = {"http": f"{proxy_type}://{user}:{password}@{url}:{port}"}
        else:
            proxy_info = {"http": f"{proxy_type}://{url}:{port}"}

        proxy_info["https"] = proxy_info["http"]

        return proxy_info

    def is_valid_port(self, port):
        """
        Method to check if the given port is valid or not
        :param port: port number to be validated
        :type port: ``int``
        """
        try:
            return 0 < int(port) <= 65535
        except ValueError:
            return False


if __name__ == "__main__":
    admin.init(splunk_ta_snow_rh_oauth2_token, admin.CONTEXT_APP_AND_USER)
