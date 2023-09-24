#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

# Always put this line at the beginning of this file
import import_declare_test  # isort: skip # noqa: F401

import sys

import modalert_snow_incident_helper
from alert_actions_base import ModularAlertBase


class AlertActionWorkerSnowIncident(ModularAlertBase):
    def __init__(self, ta_name, alert_name):
        super(AlertActionWorkerSnowIncident, self).__init__(ta_name, alert_name)

    def validate_params(self):

        if not self.get_param("account"):
            self.log_error("account is a mandatory parameter, but its value is None.")
            return False

        return True

    def process_event(self, *args, **kwargs):
        status = 0
        try:
            if not self.validate_params():
                return 3
            status = modalert_snow_incident_helper.process_event(self, *args, **kwargs)
        except (AttributeError, TypeError) as ae:
            self.log_error(
                "Error: {}. Double check spelling and also verify that a compatible version of "
                "Splunk_SA_CIM is installed.".format(ae)
            )
            return 4
        except Exception as e:
            msg = "Unexpected error: {}."
            if str(e):
                self.log_error(msg.format(str(e)))
            else:
                import traceback

                self.log_error(msg.format(traceback.format_exc()))
            return 5
        return status


if __name__ == "__main__":
    exitcode = AlertActionWorkerSnowIncident("Splunk_TA_snow", "snow_incident").run(
        sys.argv
    )
    sys.exit(exitcode)
