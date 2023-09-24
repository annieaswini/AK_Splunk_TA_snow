#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import json
import os.path as op
import traceback
from urllib.parse import urlencode

import framework.log as log
import requests
from framework import rest, utils
from solnlib import conf_manager


class SnowOAuth(object):
    def __init__(self, config, log_file="main"):
        self.logger = log.Logs().get_logger(log_file)
        self.host = config["url"]
        if not self.host.endswith("/"):
            self.host = "{0}/".format(self.host)

        self.config = config
        self.oauth_client_id = config["client_id"]
        self.oauth_client_secret = config["client_secret"]
        self.oauth_access_token = config["access_token"]
        self.oauth_refresh_token = config["refresh_token"]
        self.app_name = op.basename(op.dirname(op.dirname(op.abspath(__file__))))
        self.account_cfm = conf_manager.ConfManager(
            self.config["session_key"],
            self.app_name,
            realm="__REST_CREDENTIAL__#{}#configs/conf-splunk_ta_snow_account".format(
                self.app_name
            ),
        )

    def regenerate_oauth_access_tokens(self):
        """
        This function will be used to regenerate a new access token for
        continuing the data collection using the stored refresh token
        """

        snow_token_regeneration_url = "{}/oauth_token.do".format(self.host)
        error_message = "Unknown error occurred"
        update_status = True

        proxy_info = rest.build_proxy_info(self.config)
        session_key = self.config["session_key"]
        sslconfig = utils.get_sslconfig(self.config, session_key, self.logger)
        self.logger.info("Generating a new access token...")
        response, content = None, None

        data = {
            "grant_type": "refresh_token",
            "client_id": self.oauth_client_id,
            "client_secret": self.oauth_client_secret,
            "refresh_token": self.oauth_refresh_token,
        }
        headers = {
            "Content-type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        try:
            # semgrep ignore reason: we have custom handling for unsuccessful HTTP status codes
            response = requests.request(  # nosemgrep: python.requests.best-practice.use-raise-for-status.use-raise-for-status  # noqa: E501
                "POST",
                snow_token_regeneration_url,
                headers=headers,
                data=urlencode(data),
                proxies=proxy_info,
                timeout=120,
                verify=sslconfig,
            )

            content = json.loads(response.content)

            if response.status_code != 200:
                error_message = rest.code_to_msg(
                    response, content.get("error", content)
                )

                self.logger.error(
                    "Error occurred while regenerating the access token. Status={}, Reason={}".format(
                        response.status_code, error_message
                    )
                )
                update_status = False
                return update_status

            # New access token generated successfully
            self.update_access_token_in_conf_file(content)
            self.logger.info(
                "New access token generated and saved successfully in the configuration file"
            )

        except Exception:
            self.logger.error(
                "Failure occurred while connecting to {0}. The reason for failure={1}.".format(
                    snow_token_regeneration_url, traceback.format_exc()
                )
            )
            update_status = False

        return update_status

    def update_access_token_in_conf_file(self, content):
        """
        This function is used to update the configuration file with the new access token
        """

        self.logger.debug("Saving the newly generated access token...")

        encrypt_fields = {
            "access_token": str(content["access_token"]),
            "refresh_token": str(content["refresh_token"]),
            "client_secret": str(self.config["client_secret"]),
        }

        if self.config.get("password"):
            encrypt_fields["password"] = self.config["password"]

        # Get account conf
        account_conf = self.account_cfm.get_conf("splunk_ta_snow_account", refresh=True)

        account_conf.update(
            self.config["account"], encrypt_fields, encrypt_fields.keys()
        )

    def get_account_oauth_tokens(self, session_key, account_name):
        """
        This is a helper function to get oauth tokens from splunk_ta_snow_account.conf file
        """
        self.logger.debug(
            "Getting oauth tokens from configuration file for account '{}'".format(
                account_name
            )
        )

        token_details = {}
        account_cfm = conf_manager.ConfManager(
            session_key,
            self.app_name,
            realm="__REST_CREDENTIAL__#{}#configs/conf-splunk_ta_snow_account".format(
                self.app_name
            ),
        )
        splunk_ta_snow_account_conf = account_cfm.get_conf(
            "splunk_ta_snow_account"
        ).get_all()

        # Verifying if desired account information is present in the configuration file
        if account_name in splunk_ta_snow_account_conf:
            stanza_details = splunk_ta_snow_account_conf[account_name]

            token_details = {
                "access_token": stanza_details["access_token"],
                "refresh_token": stanza_details["refresh_token"],
            }
        else:
            self.logger.error(
                "Unable to find details of account='{}' from the configuration file".format(
                    account_name
                )
            )

        return token_details
