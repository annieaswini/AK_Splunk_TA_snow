#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import os
import sys
import traceback

import framework.log as log
import snow_consts
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

_LOGGER = log.Logs().get_logger("splunk_ta_snow_migration")
log.Logs().set_level("DEBUG")


def get_session_key():
    """
    This function is used to get the session key.
    :return: This function returns the session_key value.
    """

    session_key = sys.stdin.readline().strip()
    return session_key


def file_exist(file_name, ta_name):
    """
    This function is used to check if the file exists or not.
    :param file_name: Name of the file which is to be checked if it exists or not.
    :param ta_name: Name of the app.
    :return boolean value after checking if the file exists or not.
    """

    file_path = make_splunkhome_path(["etc", "apps", ta_name, "local", file_name])
    file_name = "".join([file_path, ".conf"])
    return os.path.exists(file_name)


def check_has_migrated_value(cfm, stanza):
    """
    This function is used to check the value of the has_migrated parameter in the splunk_ta_snow_settings.conf file.
    :param cfm: Object of the ConfManager to perform operations on the conf files.
    :param stanza: Name of the stanza to check the value of filter_parameter_migration.
    :return has_migrated param value from the splunk_ta_snow_settings.conf file.
    """

    has_migrated = "0"
    try:
        cfm_settings_conf = cfm.get_conf(snow_consts.SETTINGS_CONF_FILE, refresh=True)
        filter_parameter_migration_exist = cfm_settings_conf.stanza_exist(stanza)
        if filter_parameter_migration_exist:
            has_migrated = cfm_settings_conf.get(stanza).get("has_migrated") or "0"

        return has_migrated

    except Exception:
        _LOGGER.error(
            f"Error reading 'has_migrated' value under '{stanza}' stanza: {traceback.format_exc()}"
        )
        return has_migrated


def update_settings_conf(cfm, stanza_name):
    """
    This function is used to update the migration stanza in splunk_ta_snow_settings.conf file.
    :param session_key: The session key value.
    :param stanza_name: The name of the stanza for which the value needs to be updated.
    """

    update_dict = {}
    try:
        cfm_settings_conf = cfm.get_conf(snow_consts.SETTINGS_CONF_FILE, refresh=True)
        update_dict["has_migrated"] = 1
        cfm_settings_conf.update(stanza_name, update_dict)
    except Exception:
        _LOGGER.error(
            f"Exception occurred while updating '{stanza_name}' stanza in splunk_ta_snow_settings.conf: ",
            f"{traceback.format_exc()}",
        )
