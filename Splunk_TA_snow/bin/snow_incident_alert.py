#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import re
import socket
import sys
import traceback

import framework.utils as utils
import snow_incident_base as sib
import snow_utility as su
import splunk.clilib.cli_common as com
import splunk.Intersplunk as si


class SnowIncidentAlert(sib.SnowIncidentBase):
    def __init__(self):

        # set session key
        self.sessionkey = self._set_session_key()

        self.settings = {}

        # read input
        self.res = self._set_events()

        self.splunk_url = self._set_splunk_url()

        # no events found
        if not self.res:
            sys.exit(0)

        # get account name
        for event in self.res:
            self.account = event.get("account", None)
            self.create_multiple = event.get("is_multiple", False)
            if self.account:
                break
        if not self.account:
            self._handle_error(
                'Field "account" is required by ServiceNow for creating incidents'
            )

        super(SnowIncidentAlert, self).__init__()

    def _get_events(self):
        if not utils.is_true(self.create_multiple):
            # keeps only the first element from list of 'n' results
            # hence it creates only one incident on the snow instance
            self.res = [self.res[0]]

        return self.res

    def _set_events(self):
        """
        Fetch inputs from the search results
        """
        return si.readResults(sys.stdin, self.settings, True)

    def _set_splunk_url(self):
        KEY_WEB_SSL = "enableSplunkWebSSL"
        isWebSSL = utils.is_true(com.getWebConfKeyValue(KEY_WEB_SSL))
        webPrefix = isWebSSL and "https://" or "http://"
        port = com.getWebConfKeyValue("httpport")
        hostname = socket.gethostname()
        return "{}{}:{}/app/{}/@go?sid={}".format(
            webPrefix, hostname, port, self.settings["namespace"], self.settings["sid"]
        )

    def _prepare_data(self, event):
        if "splunk_url" not in event:
            event.update({"splunk_url": self.splunk_url})
        return super(SnowIncidentAlert, self)._prepare_data(event)

    def _set_session_key(self):
        """
            When called as custom search script, splunkd feeds the following
            to the script as a single line
            'authString:<auth><userId>admin</userId><username>admin</username>\
                <authToken><32_character_long_uuid></authToken></auth>'
        """
        import urllib.parse

        session_key = sys.stdin.readline()
        m = re.search("authToken>(.+)</authToken", session_key)
        if m:
            session_key = m.group(1)
        session_key = urllib.parse.unquote(session_key.encode("ascii").decode("ascii"))
        session_key = session_key.encode().decode("utf-8")
        return session_key

    def _get_session_key(self):
        return self.sessionkey

    def _prepare_final_result(self, resp, result):
        """Prepares the final result with the actual values
        :param `resp`: dict of the API response received
        :param `result`: dict of the formatted API response
        """
        result["Incident Number"] = resp.get("number", result.get("Incident Number"))
        result["Incident Link"] = "{}incident.do?sysparm_query=number={}".format(
            self.snow_account["url"], resp.get("number")
        )
        result["Sys Id"] = resp.get("sys_id", result.get("Sys Id"))
        result["Created"] = resp.get("sys_created_on", result.get("Created"))
        result["Priority"] = resp.get("priority", result.get("Priority"))
        result["State"] = resp.get("state", result.get("State"))
        result["Updated"] = resp.get("sys_updated_on", result.get("Updated"))
        result["Category"] = resp.get("category", result.get("Category"))
        result["Contact Type"] = resp.get("contact_type", result.get("Contact Type"))
        result["Short Description"] = resp.get(
            "short_description", result.get("Short Description")
        )
        result["Splunk URL"] = resp.get(
            "x_splu2_splunk_ser_splunk_url", result.get("Splunk URL")
        )
        result["Correlation ID"] = resp.get(
            "correlation_id", result.get("Correlation ID")
        )
        result["ciIdentifier"] = resp.get("cmdb_ci", result.get("ciIdentifier"))

        return result

    def _handle_error(self, msg="Failed to create ticket."):
        # implemented an empty method to bypass failure of erroneous incident creation with
        # valid error logs and continue with incident creation of trailing incidents.
        pass

    def _get_failure_message(self):
        return {"Error Message": "Failed to create ticket."}

    def _get_result(self, resp):
        """Get and prepare the results from the API response.
        :param `resp`: dict of the API response received
        :return `result`: dict of the formatted API response
        """
        result = {
            "Incident Link": resp.get("sys_target_sys_id", {}).get("link"),
            "Incident Number": "",
            "Short Description": resp.get("short_description"),
            "Priority": resp.get("priority"),
            "Category": resp.get("category"),
            "Created": resp.get("sys_created_on"),
            "Updated": resp.get("sys_updated_on"),
            "Contact Type": resp.get("contact_type"),
            "ciIdentifier": resp.get("configuration_item"),
            "State": resp.get("state"),
            "Sys Id": resp.get("sys_id"),
            "Correlation ID": resp.get("correlation_id"),
            "Splunk URL": resp.get("splunk_url"),
            "Incident Creation": resp.get("sys_import_state"),
        }

        if "scripted_endpoint" in dir(self):
            result = self._prepare_final_result(resp, result)
            if not result.get("Incident Number") or not result.get("Correlation ID"):
                self.logger.error(
                    "Failed to fetch Incident Number or Correlation ID."
                    " Please check that Incident Number and Correlation ID are returned from the scripted endpoint."
                )
            return result

        if su.get_selected_api(self.sessionkey, self.logger) == "import_set_api":
            snow_url = resp.get("record_link")
            result = {"Incident Creation": resp.get("status")}
            final_result = {}
        else:
            # Final result would be same as result of the Intermediate table
            # when there is failure in fatching the information from Incident table
            final_result = result
            snow_url = resp.get("sys_target_sys_id", {}).get("link")

        # Executing http request to get incident details from the Incident table of ServiceNow
        self.logger.info("Getting details of the incident from the Incident table")
        response, content = self.execute_http_request(snow_url)

        if response and content:
            if response.status_code in (200, 201):
                # getting the incident information from the Incident table.
                # In case if it fails to get the information from the incident table
                # it will fetch the fields values of intermediate table if "Table API" is being used
                resp = self._get_resp_record(content)
                final_result = self._prepare_final_result(resp, result)
            else:
                self.logger.error(
                    "Failed to get incident information. Return status code is {0}.".format(
                        response.status_code
                    )
                )
                self.logger.error(traceback.format_exc())

        if not final_result:
            # Returning an error when there is an issue getting incident information while using "Import Set API"
            return {"error": "Failed to get incident information"}
        return final_result


def main():
    handler = SnowIncidentAlert()
    handler.handle()


if __name__ == "__main__":
    main()
