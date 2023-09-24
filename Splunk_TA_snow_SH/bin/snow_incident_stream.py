#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import re
import socket
import sys
from typing import Any, Dict

import framework.utils as utils
import snow_incident_base as sib
import snow_utility as su
import splunk.clilib.cli_common as com
import splunk.Intersplunk as si


class SnowIncidentStream(sib.SnowIncidentBase):
    def __init__(self):

        # set session key
        self.sessionkey = self._set_session_key()

        self.settings = {}

        # read input
        self.res = self._set_events()
        # no events found
        if not self.res:
            sys.exit(0)

        # get default splunk_url
        self.splunk_url = self._set_splunk_url()

        # get account name
        for event in self.res:
            self.account = event.get("account", None)
            if self.account:
                break
        if not self.account:
            self._handle_error(
                'Field "account" is required by ServiceNow for creating incidents'
            )

        super(SnowIncidentStream, self).__init__()

    def _get_events(self):
        return self.res

    def _set_events(self):
        return si.readResults(sys.stdin, self.settings, True)

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

    def _handle_error(self, msg="Failed to create ticket."):
        # implemented an empty method to bypass failure of erroneous incident creation with
        # valid error logs and continue with incident creation of trailing incidents.
        pass

    def _get_failure_message(self):
        return {"Error Message": "Failed to create ticket."}

    def _get_incident_failure_message(self):
        return {"Error Message": "Failed to create ticket."}

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
        return super(SnowIncidentStream, self)._prepare_data(event)

    def _get_result(self, resp: Dict[str, Any]) -> Dict:
        if su.get_selected_api(self.sessionkey, self.logger) == "import_set_api":
            return self._get_result_of_import_set_api(resp)

        return super()._get_result(resp)


def main():
    handler = SnowIncidentStream()
    handler.handle()


if __name__ == "__main__":
    main()
