#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import json
import os
import re
import socket
import time
import uuid

import snow_ticket as st
import splunk.Intersplunk as si
from snow_utility import split_string_to_dict


class SnowEventBase(st.SnowTicket):
    """
    Create ServiceNow Event automatically by running as a callback script
    when the corresponding alert is fired
    """

    def _prepare_data(self, event):
        host = event.get("host", socket.gethostname())
        event_data = {"event_class": f"Splunk-{host}", "source": "Splunk-TA"}

        # (field_name, default_value)
        fields = (
            ("node", None),
            ("resource", None),
            ("type", None),
            ("severity", None),
            ("description", ""),
            ("time_of_event", ""),
            ("custom_fields", ""),
        )

        for field, default_val in fields:
            if field == "custom_fields" and event.get(field):
                event_data = split_string_to_dict(event_data, event[field])
                if event_data.get("Error Message"):
                    self.logger.error(event_data["Error Message"])
                    si.parseError(event_data["Error Message"])
            else:
                val = event.get(field, default_val)
                if val is None:
                    msg = (
                        'Field "{}" is required by ServiceNow '
                        "for creating events".format(field)
                    )
                    self.logger.error(msg)
                    self._handle_error(msg)
                event_data[field] = val

        if "ciIdentifier" in event:
            event_data["ci_identifier"] = event["ciIdentifier"]
        elif "ciidentifier" in event:
            event_data["ci_identifier"] = event["ciidentifier"]
        else:
            event_data["ci_identifier"] = event.get("ci_identifier", "")

        ci_ident = {}
        if event_data["ci_identifier"].strip() not in ["", "{}"]:
            ci_ident = split_string_to_dict(ci_ident, event["ci_identifier"])
            if ci_ident.get("Error Message"):
                self.logger.error(ci_ident["Error Message"])
                si.parseError(ci_ident["Error Message"])
        event_data["ci_identifier"] = json.dumps(ci_ident, ensure_ascii=False)

        additional_info = {
            "url": "",
        }
        additional_info["correlation_id"] = uuid.uuid4().hex

        if os.environ.get("SPLUNK_ARG_6"):
            # Setting default value of Splunk URL
            additional_info["url"] = os.environ["SPLUNK_ARG_6"]
        if event.get("url"):
            # Commands and alert actions put Splunk sid URL in the 'url' key.
            additional_info["url"] = event.pop("url", "")
        if event.get("additional_info"):
            # To handle the upgrade scenario from add-on v7.1.1 or before to later
            # the regex will check whether value of 'additional_info' parameter contains single url string or not.
            # Example: <scheme>://<hostname>?<arg>=<value>
            regex = (
                r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+"
                r"|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
            )
            if bool(re.match(regex, event.get("additional_info"))):
                # Here the value of 'additional_info' would be splunk url string only
                additional_info["url"] = event.get("additional_info")
                self.logger.warning(
                    "Found the 'additional_info' as a single string value. Please update the 'additional_info' "
                    "parameter as per the Splunk add-on for ServiceNow documentation."
                )
            else:
                # The code flow will reach here when 'additional_info' parameter does not have single string of url
                # Example: key1=value1||key2=value2
                # When additional_info is passed in commands or alert action in the key-value format,
                # it will be handled here and converted to a dict.
                additional_info = split_string_to_dict(
                    additional_info, event["additional_info"]
                )
                if additional_info.get("Error Message"):
                    self.logger.error(additional_info["Error Message"])
                    si.parseError(additional_info["Error Message"])

        # Setting the 'ensure_ascii' to False to parse the string in
        # the expected format as per the system's locale.
        event_data["additional_info"] = json.dumps(additional_info, ensure_ascii=False)

        if not event_data["time_of_event"]:
            event_data["time_of_event"] = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.gmtime()
            )
        return event_data

    def _get_endpoint(self):
        return "api/now/table/em_event"

    def _get_table(self):
        return "em_event"

    def _get_result(self, resp):
        res = {
            "Time of the event": resp["time_of_event"],
            "Source": resp["source"],
            "Node": resp["node"],
            "Type": resp["type"],
            "Resource": resp["resource"],
            "State": resp["state"],
            "Severity": resp["severity"],
            "Sys Id": resp["sys_id"],
            "Event Link": self._get_ticket_link(resp["sys_id"]),
        }

        return res
