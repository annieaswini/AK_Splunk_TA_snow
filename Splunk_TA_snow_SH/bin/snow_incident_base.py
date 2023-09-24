#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import base64
import json
import os
import traceback
import uuid
from typing import Any, Dict

import requests
import snow_oauth_helper as soauth
import snow_ticket as st
import splunk.Intersplunk as si
from framework import rest, utils
from snow_utility import split_string_to_dict


class SnowIncidentBase(st.SnowTicket):
    def _prepare_data(self, event):
        event_data = {}
        url = os.environ.get("SPLUNK_ARG_6", "")

        # (field_name, default_value)
        fields = (
            ("category", ""),
            ("short_description", ""),
            ("contact_type", ""),
            ("splunk_url", url),
            ("urgency", ""),
            ("subcategory", ""),
            ("state", "1"),
            ("comments", ""),
            ("location", ""),
            ("impact", "3"),
            ("correlation_id", ""),
            ("priority", "4"),
            ("assignment_group", ""),
            ("custom_fields", ""),
        )

        for field, default_val in fields:
            if field == "custom_fields" and event.get(field):
                event_data = split_string_to_dict(event_data, event[field])
                if event_data.get("Error Message"):
                    self.logger.error(event_data["Error Message"])
                    si.parseError(event_data["Error Message"])
                    return event_data
            else:
                val = event.get(field)
                if not val:
                    val = default_val
                event_data[field] = val

        if "ciIdentifier" in event:
            ci_ident = event["ciIdentifier"]
        elif "ciidentifier" in event:
            ci_ident = event["ciidentifier"]
        else:
            ci_ident = event.get("ci_identifier", "")
        event_data["configuration_item"] = ci_ident
        if not event_data["correlation_id"].strip():
            event_data["correlation_id"] = self._get_correlation_id(event)

        # Limiting correlation_id to 200 characters
        event_data["correlation_id"] = event_data["correlation_id"][0:200]
        self.logger.debug("event_data=%s", event_data)

        return event_data

    def _get_correlation_id(self, event):
        return uuid.uuid4().hex

    def _get_table(self):
        return "x_splu2_splunk_ser_u_splunk_incident"

    def _get_ticket_link(self, sys_id):
        link = "{}incident.do?sysparm_query=correlation_id={}".format(
            self.snow_account["url"], sys_id
        )

        return link

    def _prepare_result(self, resp: Dict[str, Any]) -> Dict:
        """Prepares the result with the values
        :param `resp`: dict of the API response received
        :return `result`: dict of the formatted API response
        """
        result = {
            "Incident Number": resp.get("number"),
            "Created": resp.get("sys_created_on"),
            "Priority": resp.get("priority"),
            "Updated": resp.get("sys_updated_on"),
            "Short description": resp.get("short_description"),
            "Category": resp.get("category"),
            "Contact Type": resp.get("contact_type"),
            "ciIdentifier": resp.get("configuration_item"),
            "State": resp.get("state"),
            "Sys Id": resp.get("sys_id"),
            "Incident Link": self._get_ticket_link(resp.get("correlation_id")),
            "Correlation ID": resp.get("correlation_id"),
            "Splunk URL": resp.get("splunk_url"),
        }

        return result

    def _get_result_of_import_set_api(self, resp: Dict[str, Any]) -> Dict:
        """Get and prepare the results from the Import Set API response.
        :param `resp`: dict of the API response received
        :return `result`: dict of the formatted API response
        """
        self.logger.info("Getting details of the incident from the Incident table")
        snow_url = resp.get("record_link")
        # Executing http request to get incident details from the Incident table of ServiceNow
        response, content = self.execute_http_request(snow_url)
        result: Dict[str, Any] = {"error": "Failed to get incident information"}
        if response and content:
            if response.status_code in (200, 201):
                # getting the incident information from the Incident table.
                resp = self._get_resp_record(content)
                result = self._prepare_result(resp)
                # Overriding some of the parameter considering the Incident table response
                result["ciIdentifier"] = resp.get("cmdb_ci")
                result[
                    "Incident Link"
                ] = f'{self.snow_account["url"]}incident.do?sysparm_query=number={resp.get("number")}'
                result["Splunk URL"] = resp.get("x_splu2_splunk_ser_splunk_url")
            else:
                self.logger.error(
                    "Failed to get incident information. Return status code is {0}.".format(
                        response.status_code
                    )
                )
                self.logger.error(traceback.format_exc())

        return result

    def _get_result(self, resp):
        return self._prepare_result(resp)

    def _handle_response(self, response, content):
        if response.status_code in (200, 201):
            resp = self._get_resp_record(content)
            # Below condition is to check whether the response contain
            # the "Error Message" or not when using Import Set API
            if resp and len(resp) == 1 and resp.get("Error Message"):
                return resp
            if resp and resp.get("sys_row_error"):
                error_url = resp["sys_row_error"]["link"]

                error_response, error_content = self.execute_http_request(error_url)
                if error_response and error_content:
                    if error_response.status_code == 200:
                        self.logger.error(
                            "Error Message: {0}".format(
                                json.loads(error_content)["result"]["error_message"]
                            )
                        )
                        return {
                            "Error Message": json.loads(error_content)["result"][
                                "error_message"
                            ]
                        }
                    else:
                        self.logger.error(
                            "Failed to get error message of Incident creation failure. "
                            "Status code: {}, response: {}".format(
                                error_response.status_code, error_content
                            )
                        )
                        return {
                            "Error Message": "Failed to get error message of Incident creation failure. "
                            "Status code: {}, response: {}".format(
                                error_response.status_code, error_content
                            )
                        }

        return super(SnowIncidentBase, self)._handle_response(response, content)

    def execute_http_request(self, rest_uri, method="GET", data=None, msg=""):
        """
        This is a helper function will execute the rest api call to the
        ServiceNow instance based on the authentication type selected by the user
        """

        headers = {"Content-type": "application/json", "Accept": "application/json"}
        response = None
        content = None

        proxy_info = rest.build_proxy_info(self.snow_account)
        session_key = self.snow_account["session_key"]
        sslconfig = utils.get_sslconfig(self.snow_account, session_key, self.logger)

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

        # Executing the rest api call
        try:
            for retry in range(3):
                # Reloading the headers with the regenerated oauth access token
                if retry > 0 and self.snow_account["auth_type"] == "oauth":
                    self.logger.info("Retry count: {}/3".format(retry + 1))
                    headers.update(
                        {
                            "Authorization": "Bearer %s"
                            % self.snow_account["access_token"]
                        }
                    )

                self.logger.info("Initiating request to {}".format(rest_uri))

                # semgrep ignore reason: we have custom handling for unsuccessful HTTP status codes
                response = requests.request(  # nosemgrep: python.requests.best-practice.use-raise-for-status.use-raise-for-status  # noqa: E501
                    method,
                    rest_uri,
                    headers=headers,
                    data=data,
                    proxies=proxy_info,
                    timeout=120,
                    verify=sslconfig,
                )
                content = response.content

                if response.status_code not in (200, 201):
                    # If HTTP status = 401, there is a possibility that access token is expired if auth_type = oauth
                    if (
                        response.status_code == 401
                        and self.snow_account["auth_type"] == "oauth"
                    ):
                        self.logger.error(
                            "Failure occurred while connecting to {0}. The reason for failure={1}. Failure "
                            "potentially caused by expired access token. Regenerating access token.".format(
                                rest_uri, response.reason
                            )
                        )
                        snow_oauth = soauth.SnowOAuth(self.snow_account, "ticket")
                        update_status = snow_oauth.regenerate_oauth_access_tokens()

                        if update_status:
                            # Reloading the self.snow_account dictionary with the new tokens generated
                            self.snow_account = self._get_service_now_account()
                            continue
                        else:
                            self.logger.error(
                                "Unable to generate new access token. Failure potentially caused by "
                                "the expired refresh token. To fix the issue, reconfigure the account and try again."
                            )
                            break

                    # Error is not related to access token expiration. Hence breaking the loop
                    else:
                        break
                # Response obtained successfully. Hence breaking the loop
                else:
                    break

        except Exception:
            if msg:
                self.logger.error(msg)
            self.logger.error(traceback.format_exc())

        self.logger.info("Ending request to {}".format(rest_uri))
        return response, content

    def _get_incident_failure_message(self):
        return None
