#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import os
import os.path as op
import sys

sys.path.insert(0, op.dirname(op.dirname(op.abspath(__file__))))

import snow_incident_base as sib  # noqa: E402
import snow_ticket as st  # noqa: E402


class AutoSnowIncident(sib.SnowIncidentBase):
    """
    Create ServiceNow Incident automatically by running as a callback script
    when the corresponding alert is fired
    """

    def __init__(self):
        self.account = st.get_account(os.environ["SPLUNK_ARG_8"])
        super(AutoSnowIncident, self).__init__()

    def _get_events(self):
        return st.read_alert_results(os.environ["SPLUNK_ARG_8"], self.logger)


def main():
    handler = AutoSnowIncident()
    handler.handle()


if __name__ == "__main__":
    main()
