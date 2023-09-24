#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import socket
import sys
from typing import Any, Dict

import framework.utils as utils
import snow_incident_base as sib
import snow_ticket as st
import snow_utility as su
import splunk.clilib.cli_common as com
import splunk.Intersplunk as si


class ManualSnowIncident(sib.SnowIncidentBase):
    """
    Create ServiceNow incident manually by running the script and passing
    in the correct parameters
    """

    def __init__(self):
        self.subcommand = "create"
        self.snow_account = {}

        # Read input and get account name
        res = self._get_events()

        self.account = res[0].get("account", None)

        super(ManualSnowIncident, self).__init__()

        # Get default URL if not passed
        self.settings = {}
        self.splunk_url = self._set_splunk_url()

    def _get_events(self):
        """
        This function is used to parse input parameters
        :return: rec : tuple
        """
        create_parser = st.ArgumentParser()

        # create subcommand
        create_parser.add_argument(
            "--account",
            dest="account",
            type=str,
            action="store",
            required=True,
            help="Account for which command is to be executed",
        )
        create_parser.add_argument(
            "--category",
            dest="category",
            type=str,
            action="store",
            help="Category of the incident",
        )
        create_parser.add_argument(
            "--short_description",
            dest="short_description",
            type=str,
            action="store",
            help="Short description of the incident",
        )
        create_parser.add_argument(
            "--contact_type",
            dest="contact_type",
            type=str,
            action="store",
            help="Contact type of the incident",
        )
        create_parser.add_argument(
            "--urgency",
            dest="urgency",
            type=int,
            action="store",
            default=3,
            help="Urgency of the incident",
        )
        create_parser.add_argument(
            "--subcategory",
            dest="subcategory",
            type=str,
            action="store",
            default="",
            help="Subcategory of the incident",
        )
        create_parser.add_argument(
            "--state",
            dest="state",
            type=int,
            action="store",
            default=1,
            help="State of the incident",
        )
        create_parser.add_argument(
            "--location",
            dest="location",
            type=str,
            action="store",
            default="",
            help="Location of the incident",
        )
        create_parser.add_argument(
            "--impact",
            dest="impact",
            type=int,
            action="store",
            default=3,
            help="Impact of the incident",
        )
        create_parser.add_argument(
            "--priority",
            dest="priority",
            type=int,
            action="store",
            default=4,
            help="Priority of the incident",
        )
        create_parser.add_argument(
            "--assignment_group",
            dest="assignment_group",
            type=str,
            action="store",
            default="",
            help="Assignment groups",
        )
        if self.snow_account:
            create_parser.add_argument(
                "--opened_by",
                dest="opened_by",
                type=str,
                action="store",
                default=self.snow_account.get("username", ""),
                help="Opened by",
            )
        else:
            create_parser.add_argument(
                "--opened_by",
                dest="opened_by",
                type=str,
                action="store",
                help="Opened by",
            )
        create_parser.add_argument(
            "--ci_identifier",
            dest="ci_identifier",
            type=str,
            action="store",
            default="",
            help="Optional JSON string that represents "
            "a configuration item in the users network",
        )

        create_parser.add_argument(
            "--comments",
            dest="comments",
            type=str,
            action="store",
            default="",
            help="Incident comments",
        )
        create_parser.add_argument(
            "--splunk_url",
            dest="splunk_url",
            type=str,
            action="store",
            default="",
            help="Splunk deepdive URL",
        )
        create_parser.add_argument(
            "--correlation_id",
            dest="correlation_id",
            type=str,
            action="store",
            default="",
            help="Splunk deepdive URL",
        )
        create_parser.add_argument(
            "--custom_fields",
            dest="custom_fields",
            type=str,
            action="store",
            default="",
            help="Splunk Custom Fields",
        )
        opts = create_parser.parse_args()
        # self.subcommand = opts.subcommand

        if self.subcommand == "update":
            self.sys_id = opts.sys_id[0:200]
            return (
                {
                    "u_state": opts.state,
                },
            )
        else:
            rec = {
                "category": opts.category,
                "short_description": opts.short_description,
                "contact_type": opts.contact_type,
                "urgency": str(opts.urgency),
                "subcategory": opts.subcategory,
                "state": str(opts.state),
                "location": opts.location,
                "impact": str(opts.impact),
                "priority": str(opts.priority),
                "assignment_group": opts.assignment_group,
                "opened_by": opts.opened_by,
                "ciidentifier": opts.ci_identifier,
                "account": opts.account,
            }

            rec["custom_fields"] = opts.custom_fields
            rec["comments"] = opts.comments
            rec["splunk_url"] = opts.splunk_url
            rec["correlation_id"] = opts.correlation_id[0:200]
            return (rec,)

    def _set_splunk_url(self):
        # Parse the stdin to get namespace and search id
        si.readResults(sys.stdin, self.settings, True)

        KEY_WEB_SSL = "enableSplunkWebSSL"
        isWebSSL = utils.is_true(com.getWebConfKeyValue(KEY_WEB_SSL))
        webPrefix = isWebSSL and "https://" or "http://"
        port = com.getWebConfKeyValue("httpport")
        hostname = socket.gethostname()
        return "{}{}:{}/app/{}/@go?sid={}".format(
            webPrefix, hostname, port, self.settings["namespace"], self.settings["sid"]
        )

    def _prepare_data(self, event):
        if not event.get("splunk_url"):
            event.update({"splunk_url": self.splunk_url})
        return super(ManualSnowIncident, self)._prepare_data(event)

    def _get_result(self, resp: Dict[str, Any]) -> Dict:
        if su.get_selected_api(self.session_key, self.logger) == "import_set_api":
            return self._get_result_of_import_set_api(resp)

        return super()._get_result(resp)


def main():
    handler = ManualSnowIncident()
    handler.handle()


if __name__ == "__main__":
    main()
