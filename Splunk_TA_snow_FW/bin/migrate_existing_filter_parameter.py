#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import traceback

import framework.log as log
import snow_consts
import splunk_ta_snow_migration_utility as utility
from solnlib import conf_manager

_LOGGER = log.Logs().get_logger("splunk_ta_snow_migration")
log.Logs().set_level("DEBUG")


class MigrateExistingFilterParameter:
    """
    This class is used to migrate the existing filter parameter in inputs.conf file.
    """

    def update_inputs_conf(self, cfm):
        """
        This function is used to update the inputs.conf file.
        :param session_key: The session_key value.
        """
        cfm_inputs_conf = cfm.get_conf("inputs")
        inptus_conf_obj = cfm_inputs_conf.get_all()
        input_items = list(inptus_conf_obj.items())
        if input_items:
            for input_stanza, input_info in input_items:
                if (
                    input_stanza[:7] == "snow://"
                    and input_info.get("filter_data") is not None
                ):
                    filter_data = input_info.get("filter_data", "")
                    # Replacing '&' with '^' as per ServiceNow syntax
                    filter_data = filter_data.replace("&", "^")
                    # Replacing '|' with '^OR' as per ServiceNow syntax
                    filter_data = filter_data.replace("|", "^OR")
                    cfm_inputs_conf.update(input_stanza, {"filter_data": filter_data})

    def migrate_existing_filter_data(self):
        """
        This function is used to migrate the existing filter parameter value to the ServiceNow syntax.
        """
        try:
            has_migrated = "0"
            session_key = utility.get_session_key()
            cfm = conf_manager.ConfManager(session_key, snow_consts.APP_NAME)
            setting_conf_exist = utility.file_exist(
                snow_consts.SETTINGS_CONF_FILE, snow_consts.APP_NAME
            )
            if setting_conf_exist:
                has_migrated = utility.check_has_migrated_value(
                    cfm, snow_consts.FILTER_PARAMETER_MIGRATION_STANZA
                )

            if has_migrated == "0":
                _LOGGER.debug(
                    "filter parameter has not been migrated yet. Proceeding to migrate filter parameter."
                )
                self.update_inputs_conf(cfm)
                utility.update_settings_conf(
                    cfm, snow_consts.FILTER_PARAMETER_MIGRATION_STANZA
                )
                _LOGGER.info("filter parameter migration has been completed.")
        except Exception:
            _LOGGER.error(
                "Error while migrating filter parameter. {} ".format(
                    traceback.format_exc()
                )
            )


if __name__ == "__main__":
    migrate_filter_parameter = MigrateExistingFilterParameter()
    migrate_filter_parameter.migrate_existing_filter_data()
