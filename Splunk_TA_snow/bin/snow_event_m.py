#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import socket
import sys
import time

import framework.utils as utils
import snow_event_base as seb
import snow_ticket as st
import splunk.clilib.cli_common as com
import splunk.Intersplunk as si


class ManualSnowEvent(seb.SnowEventBase):
    """
    Create ServiceNow Event manually by running the script and passing
    in the correct parameters
    """

    def __init__(self):
        self.subcommand = "create"
        self.sys_id = None

        # Parse input parameters
        res = self._get_events()

        # Get account name
        self.account = res[0].get("account", None)
        super(ManualSnowEvent, self).__init__()

        self.settings = {}
        # Get default URL if not passed
        self.splunk_url = self._set_splunk_url()

    def _get_events(self):
        """
        This function is used to parse input parameters
        :return: res : tuple
        """
        create_parser = st.ArgumentParser()

        # create subcommand
        create_parser.add_argument(
            "--account",
            dest="account",
            type=str,
            action="store",
            required=True,
            help="Account for which event is to be created",
        )
        create_parser.add_argument(
            "--node",
            dest="node",
            type=str,
            action="store",
            required=True,
            help="The physical device or virtual entity that is being monitored",
        )
        create_parser.add_argument(
            "--resource",
            dest="resource",
            type=str,
            action="store",
            required=True,
            help="The resource on the node that generates the event",
        )
        create_parser.add_argument(
            "--type",
            dest="type",
            type=str,
            action="store",
            required=True,
            help="Type of the event",
        )
        create_parser.add_argument(
            "--severity",
            dest="severity",
            type=str,
            action="store",
            required=True,
            help="Severity of the event",
        )
        create_parser.add_argument(
            "--source",
            dest="source",
            type=str,
            action="store",
            default="",
            help="Source of the event",
        )
        create_parser.add_argument(
            "--time_of_event",
            dest="time_of_event",
            type=str,
            action="store",
            default="",
            help='Time of the event in "YYYY-MM-DD hh:mm:ss" format',
        )
        create_parser.add_argument(
            "--ci_identifier",
            dest="ci_identifier",
            type=str,
            action="store",
            default="{}",
            help="CI identifier of the event. Pass double pipe "
            "sign delimited values e.g. key1=value1||key2=value2",
        )
        create_parser.add_argument(
            "--additional_info",
            dest="additional_info",
            type=str,
            action="store",
            default="",
            help="Additional information of the event. Pass double pipe "
            'sign delimited values e.g. key1=value one||key2= "value 2"',
        )
        create_parser.add_argument(
            "--description",
            dest="description",
            type=str,
            action="store",
            default="",
            help="Description of the event",
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
            self.sys_id = opts.sys_id
            return {
                "state": opts.state,
            }
        else:
            if not opts.time_of_event:
                time_of_event = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            else:
                time_of_event = opts.time_of_event

            res = {
                "node": opts.node,
                "resource": opts.resource,
                "type": opts.type,
                "severity": opts.severity,
                "source": opts.source,
                "time_of_event": time_of_event,
                "ci_identifier": opts.ci_identifier,
                "additional_info": opts.additional_info,
                "description": opts.description,
                "account": opts.account,
                "custom_fields": opts.custom_fields,
            }

            res["event_class"] = "Splunk"
            return (res,)

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
        event.update({"url": self.splunk_url})
        return super(ManualSnowEvent, self)._prepare_data(event)


def main():
    handler = ManualSnowEvent()
    handler.handle()


if __name__ == "__main__":
    main()
