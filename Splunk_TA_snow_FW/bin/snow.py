#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import os
import os.path as op
import re
import sys
import traceback
import urllib.parse
from datetime import datetime

import framework.configure as conf
import framework.log as log
import framework.utils as utils
import snow_consts
from solnlib import conf_manager
from splunk import rest
from splunklib import modularinput as smi

from snow_data_loader import Snow
import snow_consts as sc
import snow_utility

utils.remove_http_proxy_env_vars()

_LOGGER = log.Logs().get_logger("main")

APP_NAME = op.basename(op.dirname(op.dirname(op.abspath(__file__))))
SESSION_KEY = "session_key"
SERVER_URI = "server_uri"
SPLUNK_HOME = os.environ["SPLUNK_HOME"]
FIELD_VALIDATION_MESSAGE = "Values can only include lower-case letters, numbers, '$', '.' and '_' characters. Got the value: {}"  # noqa: E501


def _get_datetime(when=None, input_name=None):
    if not when:
        return "now"

    when = re.sub(r"\s+", " ", when)

    # Verifying if the 'since_when' field is given in the expected format
    try:
        since = datetime.strptime(when, "%Y-%m-%d %H:%M:%S")
        current_time = datetime.utcnow()
    except ValueError:
        _LOGGER.error(
            "Got unexpected value '{}' of field 'since_when'. Enter the 'since_when' field in "
            "YYYY-DD-MM hh:mm:ss format for input '{}'.".format(when, input_name)
        )
        return None

    # Verifying if the 'since_when' field is not given a future date
    if since > current_time:
        _LOGGER.error(
            "Got unexpected value '{}' of the field 'since_when' for input '{}'. Start time of the input should "
            "not be a future date.".format(when, input_name)
        )
        return None

    return when


def _check_interval(interval, input_name):
    if not interval:
        _LOGGER.error("Field 'interval' is required for input '{}'".format(input_name))
        return False

    try:
        if 0 < int(interval) < 31536001:
            return True
        else:
            _LOGGER.error(
                "Got unexpected value {} of 'interval' field for input '{}'. "
                "Interval should be in between 1 and 31536000 seconds. "
                "You can either change it in inputs.conf file or edit "
                "'Collection interval' on Inputs page.".format(interval, input_name)
            )
            return False
    except ValueError:
        _LOGGER.error(
            "Got unexpected value {} of 'interval' field for input '{}'. Interval should be an integer. "
            "You can either change it in inputs.conf file or edit 'Collection interval' on Inputs page.".format(
                interval, input_name
            )
        )
        return False


def index_field_validation(index_value):
    """
    This function returns False and error_log string, if index field has unsupported value or
    index field length is greater than maximum supported length. Otherwise, returns True and empty string.
    """
    if len(index_value) > snow_consts.INDEX_LENGTH:
        error_log = "Maximum length allowed for index is {}.".format(
            snow_consts.INDEX_LENGTH
        )
        return False, error_log
    elif not re.match(r"""^[a-zA-Z0-9][a-zA-Z0-9\_\-]*$""", index_value):
        error_log = "Index names must begin with a letter or a number and must contain only letters, numbers, underscores, or hyphens."  # noqa: E501
        return False, error_log
    return True, ""


def validate_combined_length(filter_data, include):
    """
    This function returns False if the combined length of Filter Parameters and
    Included Properties is greater than 1000 characters. Otherwise, it returns True.
    """
    length_of_url_parameters_combined = len(filter_data or "") + len(include or "")

    if length_of_url_parameters_combined > 1000:
        return length_of_url_parameters_combined
    else:
        return 0


def special_character_validation(value_list):
    """
    This function returns False if field value has unsupported characters. Otherwise, returns true.
    """

    for value in [item.strip() for item in value_list.split(",")]:
        if re.search(r"^([a-z$_.\d]+)$", value) is None:
            _LOGGER.error(FIELD_VALIDATION_MESSAGE.format(value))
            return False
    return True


def proxy_port_value_validation(value):
    """
    This function returns False if proxy port has unsupported value. Otherwise, it returns true.
    """
    try:
        proxy_port_value = int(value)
        if proxy_port_value <= 0 or proxy_port_value > 65535:
            _LOGGER.error(
                "Field Proxy Port should be within the range of [1 and 65535]"
            )
            return False
    except ValueError:
        _LOGGER.error(
            "Invalid Proxy Port value in inputs.conf file. To start data collection please provide valid proxy port value."  # noqa: E501
        )
        return False
    except TypeError:
        _LOGGER.error(
            "No Proxy Port value in inputs.conf file. To start data collection please provide valid proxy port value."
        )
        return False
    return True


def _create_warning_msg(snow_dict, name):
    warning_msg = ""
    if len(snow_dict) > 0:
        warning_msg += (
            "Remove {0} from '{1}' stanza of {2}/etc/apps/{3}/local/service_now.conf as parameter(s) "
            "no longer used. ".format(", ".join(snow_dict), name, SPLUNK_HOME, APP_NAME)
        )

    return warning_msg


class SNOW(smi.Script):
    def __init__(self):
        super(SNOW, self).__init__()

    def get_scheme(self):
        scheme = smi.Scheme("Splunk Add-on for ServiceNow")
        scheme.description = "Enable ServiceNow database table inputs"
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                "name", title="Name", description="Name", required_on_create=True
            )
        )

        scheme.add_argument(
            smi.Argument(
                "duration",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "account",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "table",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "exclude",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "include",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "timefield",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "reuse_checkpoint",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "since_when",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "id_field",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                "filter_data",
                required_on_create=False,
            )
        )

        return scheme

    def validate_input(self, definition):
        config_metadata = definition.metadata
        config = definition.parameters

        # Check if 'interval' is an integer
        interval = config.get("interval")
        if not _check_interval(interval, config_metadata["name"]):
            raise Exception(
                "Collection interval should be an integer for input '{}', but got {}".format(
                    config_metadata["name"], interval
                )
            )

        # Check if 'since_when' conforms to the format mentioned
        if config.get("since_when"):
            when = config["since_when"]
            try:
                re.sub(r"\s+", " ", when)
                datetime.strptime(when, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                _LOGGER.error(
                    "Got unexpected value {} of 'since_when' field for input '{}'. "
                    "Enter the 'since_when' field in YYYY-DD-MM hh:mm:ss format.You can either change it in "
                    "inputs.conf file or edit 'Start date' on Inputs page.".format(
                        when, config_metadata["name"]
                    )
                )
                raise Exception(
                    "Date should be in YYYY-DD-MM hh:mm:ss format for input '{}',"
                    " but got {}".format(config_metadata["name"], when)
                )

        return

    def _get_encrypted_conf(self, conf_name):
        """
        Return the conf file retrived through legacy conf manager.
        It consists of the password in encrypted form.
        """
        self.encryption_manager.reload_confs((conf_name,))
        encrypted_conf = self.encryption_manager.get_conf("nobody", APP_NAME, conf_name)
        if not encrypted_conf:
            raise Exception("Unable to retrieve the file: {}".format(conf_name))
        return {stanza["stanza"]: stanza for stanza in encrypted_conf}

    def _encrypt_credentials(
        self, account_conf_manager, settings_conf_manager, session_key, server_uri
    ):
        """
        This method encrypts the credentials which are in clear text, both in account
        and proxy confs.
        """

        # Get the legacy password manager
        self.encryption_manager = conf.ConfManager(server_uri, session_key)
        # Fields that requires encryption
        security_fields = ["password", "access_token", "refresh_token", "client_secret"]
        # This block is in try...except as account_conf_manager.get_conf is raising exception if
        # conf file is not present
        try:
            # Get account password conf for encrypting account information
            account_conf_encrypted = self._get_encrypted_conf("splunk_ta_snow_account")
            # Get account conf
            account_conf = account_conf_manager.get_conf(
                "splunk_ta_snow_account", refresh=True
            )
            # Get all accounts
            accounts = account_conf.get_all()
        except Exception as e:
            # Exception occurred while getting splunk_ta_snow_account.conf file
            _LOGGER.error(traceback.format_exc())
            _LOGGER.error(
                "Failure occurred in accessing the splunk_ta_snow_account.conf file. Error: {}".format(
                    str(e)
                )
            )
            return

        try:
            # Iterate for each account and encrypt clear text
            for account, account_info in list(accounts.items()):
                fields_to_encrypt = {}
                # This parameter will be used to determine if encryption of the security fields is required
                need_encryption = False

                for field in security_fields:
                    if account_info.get(field):
                        fields_to_encrypt[field] = account_info[field]
                        # Checking if a field that needs to be secured is in clear text format
                        if (
                            not account_conf_encrypted[account].get(field)
                            == account_conf.ENCRYPTED_TOKEN
                        ):
                            need_encryption = True

                # Determine if encryption is required
                if need_encryption:
                    _LOGGER.info(
                        "Encrypting the clear text security fields for account={}".format(
                            account
                        )
                    )
                    account_conf.update(
                        account, fields_to_encrypt, fields_to_encrypt.keys()
                    )
        except Exception as e:
            # Exception occurred while encrypting the account credentials. Passing this exception because
            # data collection through other accounts should not be stopped because of one account
            _LOGGER.error(
                "Failed to encrypt credentials for account '{}'. Exception occurred: {}".format(
                    account, str(e)
                )
            )
            _LOGGER.error(traceback.format_exc())
            pass

        # This block is in try...except as settings_conf_manager.get_conf is raising exception if
        # conf file is not present
        try:
            # Get the settings password conf for encrypting proxy information
            settings_conf_encrypted = self._get_encrypted_conf(
                "splunk_ta_snow_settings"
            )
            # Get settings conf
            settings_conf = settings_conf_manager.get_conf(
                "splunk_ta_snow_settings", refresh=True
            )
            # Get proxy stanza
            setting = settings_conf.get("proxy")
            if setting.get("proxy_password", None):
                if (
                    not settings_conf_encrypted["proxy"].get("proxy_password")
                    == settings_conf.ENCRYPTED_TOKEN
                ):
                    _LOGGER.info("Encrypting clear password for proxy")
                    settings_conf.update(
                        "proxy",
                        {"proxy_password": setting["proxy_password"]},
                        ["proxy_password"],
                    )
        except Exception as e:
            # Pass in case settings conf not obtained while reading the proxy settings
            _LOGGER.error(
                "Failed to encrypt credentials for proxy configuration. Exception occurred: {}".format(
                    str(e)
                )
            )
            _LOGGER.error(traceback.format_exc())
            pass

    def stream_events(self, inputs, ew):
        meta_configs = self._input_definition.metadata
        stanza_configs = []

        # Verify if inputs are configured
        if not bool(inputs.inputs):
            _LOGGER.info(
                "No configured inputs found. To collect data from ServiceNow, configure new input(s) or "
                "update existing input(s) either from Inputs page of the Add-on or manually from inputs.conf."
            )
            return 0

        input_name = list(inputs.inputs.keys())[0]
        input_item = inputs.inputs.get(input_name)

        if "account" not in input_item:
            rest.simpleRequest(
                "messages",
                meta_configs[SESSION_KEY],
                postargs={
                    "severity": "error",
                    "name": "ServiceNow error message",
                    "value": "Some configurations are missing in Splunk Add-on for ServiceNow. "
                    "Fix the configurations to resume data collection.",
                },
                method="POST",
            )

        # Perform migration of duration field to interval field for multi instance mode
        if (
            input_item.get("duration")
            != "Deprecated - Please use the interval field instead"
        ):
            snow_utility.migrate_duration_to_interval(
                input_name, input_item, meta_configs, _LOGGER
            )

        # migrate file checkpoint to KV store if not already done
        if not snow_utility.is_checkpoint_migrated_to_kv(
            input_name, input_item, meta_configs, _LOGGER
        ):
            if not snow_utility.migrate_file_to_kv_checkpoint(
                input_name, input_item, meta_configs, _LOGGER
            ):
                _LOGGER.WARN(
                    "Skipping the data collection for input: {} as file checkpoint migration to KV Store failed. "
                    "Please restart the input to retry the checkpoint migration instantly. "
                    "Migration will be retried automatically on next invocation of the input.".format(
                        input_name
                    )
                )
                return

        # Check for deprecated fields in service_now.conf
        snow_default_fields = [
            "collection_interval",
            "loglevel",
            "since_when",
            "record_count",
            "disable_ssl_certificate_validation",
        ]
        snow_proxy_fields = [
            "proxy_enabled",
            "proxy_url",
            "proxy_port",
            "proxy_username",
            "proxy_password",
            "proxy_rdns",
            "proxy_type",
        ]

        # Check for fields expected in splunk_ta_snow_account.conf
        snow_basic_account_fields = ["url", "username", "password"]
        snow_oauth_account_fields = [
            "url",
            "client_id",
            "client_secret",
            "access_token",
            "refresh_token",
        ]

        try:
            service_now = conf_manager.ConfManager(
                meta_configs[SESSION_KEY],
                APP_NAME,
                realm="__REST_CREDENTIAL__#{}#configs/conf-service_now".format(
                    APP_NAME
                ),
            )

            conf_service_now = service_now.get_conf("service_now").get_all()

            warning_msg = ""

            snow_default = [
                f for f in snow_default_fields if f in conf_service_now["snow_default"]
            ]
            warning_msg += _create_warning_msg(snow_default, "snow_default")

            if "snow_account" in conf_service_now:
                snow_account = [
                    f
                    for f in snow_basic_account_fields
                    if f in conf_service_now["snow_account"]
                ]
                warning_msg += _create_warning_msg(snow_account, "snow_account")

            if "snow_proxy" in conf_service_now:
                snow_proxy = [
                    f for f in snow_proxy_fields if f in conf_service_now["snow_proxy"]
                ]
                warning_msg += _create_warning_msg(snow_proxy, "snow_proxy")

            if warning_msg:
                _LOGGER.warning(warning_msg)

        except conf_manager.ConfManagerException:
            _LOGGER.error(traceback.format_exc())

        try:
            account_cfm = conf_manager.ConfManager(
                meta_configs[SESSION_KEY],
                APP_NAME,
                realm="__REST_CREDENTIAL__#{}#configs/conf-splunk_ta_snow_account".format(
                    APP_NAME
                ),
            )

            settings_cfm = conf_manager.ConfManager(
                meta_configs[SESSION_KEY],
                APP_NAME,
                realm="__REST_CREDENTIAL__#{}#configs/conf-splunk_ta_snow_settings".format(
                    APP_NAME
                ),
            )

            # Read account, settings and snow conf files into variables
            splunk_ta_snow_settings_conf = settings_cfm.get_conf(
                "splunk_ta_snow_settings", refresh=True
            ).get_all()

            proxy_port_value = splunk_ta_snow_settings_conf["proxy"].get(
                "proxy_port", 0
            )
            if (
                utils.is_true(
                    splunk_ta_snow_settings_conf["proxy"].get("proxy_enabled") or "0"
                )
                and proxy_port_value
                and not proxy_port_value_validation(proxy_port_value)
            ):
                return

            loglevel = splunk_ta_snow_settings_conf["logging"].get("loglevel", "INFO")
            log.Logs().set_level(loglevel)
            self._encrypt_credentials(
                account_cfm,
                settings_cfm,
                meta_configs[SESSION_KEY],
                meta_configs[SERVER_URI],
            )

            try:
                splunk_ta_snow_account_conf = account_cfm.get_conf(
                    "splunk_ta_snow_account", refresh=True
                ).get_all()
            except conf_manager.ConfManagerException:
                _LOGGER.info(
                    "No account configurations found for this add-on. To start data collection, configure new "
                    "account on Configurations page and link it to an input on Inputs page. Exiting TA.."
                )
                return

            service_now_conf = account_cfm.get_conf(
                "service_now", refresh=True
            ).get_all()

            account_info = {}

            # Iterate through multiple account stanzas (if present) in account.conf
            for k, v in splunk_ta_snow_account_conf.items():
                account_info[k] = v

            input_name = list(inputs.inputs.keys())[0]
            input_item = inputs.inputs.get(input_name)

            try:
                input_item["app_name"] = APP_NAME
                input_item["name"] = input_name[
                    input_name.rfind("://") + 3 :  # noqa: E203
                ]
                # Verifying if account is linked with the enabled input
                if not input_item.get("account"):
                    _LOGGER.error(
                        "No ServiceNow account linked to the data input '{}'. To resume data collection, "
                        "either configure new account on Configurations page or link an existing account to the"
                        " input on Inputs page.".format(input_item["name"])
                    )
                    return

                # Verifying if table is linked with the enabled input
                if not input_item.get("table"):
                    _LOGGER.error(
                        "No ServiceNow database table linked to the data input '{}'. "
                        "To resume data collection, either specify table for the input "
                        "in inputs.conf file or edit 'Table' on Inputs page.".format(
                            input_item["name"]
                        )
                    )
                    return
                if input_item.get("include") and input_item.get("exclude"):
                    _LOGGER.error(
                        "Include and Exclude properties are configured for the input"
                        " '{}'. To resume data collection, please specify either of "
                        "the properties.".format(input_item["name"])
                    )
                    return

                if input_item.get("include"):
                    if not special_character_validation(input_item.get("include")):
                        _LOGGER.error(
                            "Invalid Include properties for input: {}. {}. To resume data collection, "
                            "please provide the valid values.".format(
                                input_name,
                                FIELD_VALIDATION_MESSAGE.format(input_item["include"]),
                            )
                        )
                        return

                if input_item.get("exclude"):
                    if not special_character_validation(input_item.get("exclude")):
                        _LOGGER.error(
                            "Invalid Exclude properties for input: {}. {}. To resume data collection, "
                            "please provide the valid values.".format(
                                input_name,
                                FIELD_VALIDATION_MESSAGE.format(input_item["exclude"]),
                            )
                        )
                        return

                if input_item.get("timefield"):
                    if not special_character_validation(input_item.get("timefield")):
                        _LOGGER.error(
                            "Invalid timefield for input: {}. {}. To resume data collection, please provide the valid values."
                            "".format(
                                input_name,
                                FIELD_VALIDATION_MESSAGE.format(
                                    input_item["timefield"]
                                ),
                            )
                        )
                        return

                if input_item.get("id_field"):
                    if not special_character_validation(input_item.get("id_field")):
                        _LOGGER.error(
                            "Invalid id_field for input: {}. {}. To resume data collection, please provide the valid values.".format(
                                input_name,
                                FIELD_VALIDATION_MESSAGE.format(input_item["id_field"]),
                            )
                        )
                        return

                # Convert interval value to integer
                if not input_item.get("interval"):
                    input_item["interval"] = 60
                    _LOGGER.warning(
                        "No interval specified for input '{}'."
                        "Using default interval=60 for now.".format(input_item["name"])
                    )
                elif _check_interval(input_item["interval"], input_item["name"]):
                    input_item["interval"] = int(input_item["interval"])
                else:
                    return

                # Validating index field of input
                res, error_log = index_field_validation(input_item.get("index"))
                if not res:
                    _LOGGER.error(
                        "Invalid index name for input {}."
                        "{}."
                        " You can either change index field in inputs.conf file or "
                        "edit it from the Inputs page of the add-on.".format(
                            input_name, error_log
                        )
                    )
                    return

                # Logic to specify "since_when" parameter for collecting the events
                if not input_item.get("since_when"):
                    # Getting the default start date
                    _LOGGER.info(
                        "Start date not found for the input '{}'."
                        "Setting current time as start date.".format(input_item["name"])
                    )
                    input_item["since_when"] = _get_datetime(
                        input_name=input_item["name"]
                    )
                else:
                    # Validating the configured start date for the input
                    validated_start_date = _get_datetime(
                        when=input_item["since_when"], input_name=input_item["name"]
                    )
                    # Given start date for the input is as expected
                    if validated_start_date:
                        input_item["since_when"] = validated_start_date
                    # Given start date for the input is not as expected
                    else:
                        return

                length_of_url_parameters_combined = validate_combined_length(
                    input_item.get("filter_data", ""), input_item.get("include", "")
                )
                if length_of_url_parameters_combined:
                    error_log = (
                        "The combined length of Filter Parameters and Included Properties is too long({}) "
                        "for input '{}'. The maximum permissible length is 1000 characters. You can either "
                        "change it in inputs.conf file or edit on Inputs page"
                    ).format(length_of_url_parameters_combined, input_item["name"])
                    _LOGGER.error(error_log)
                    return

                if input_item.get("filter_data"):
                    input_item["filter_data"] = urllib.parse.quote(
                        input_item["filter_data"]
                    )

                # Verify if account parameters are missing and log message for missing parameters
                account_details = account_info.get(input_item.get("account"))
                if not account_details:
                    _LOGGER.error(
                        "Specified account {} linked to input '{}' is not configured. You can either "
                        "configure account in splunk_ta_snow_account.conf file or on "
                        "Configurations page of add-on.".format(
                            input_item.get("account"), input_item["name"]
                        )
                    )
                    return

                if "record_count" in list(account_details.keys()):
                    account_record_count = account_details["record_count"]
                    try:
                        # Verify if record count parameter is integer or not
                        account_record_count = int(account_record_count)
                    except ValueError:
                        _LOGGER.error(
                            "Got unexpected value {} in 'record' field for input '{}'. Record count should be "
                            "an integer. You can either change it splunk_ta_snow_account.conf file or "
                            "edit 'Record count' on the Configuration page.".format(
                                input_item.get("account"), input_item["name"]
                            )
                        )
                        return
                    # Verify if record count parameter is between 1 and 10000
                    if account_record_count > 10000 or account_record_count < 1:
                        _LOGGER.error(
                            "Specified account {} linked to input '{}' has a record count not in range 1 "
                            "to 10000. You can either configure record count in splunk_ta_snow_account.conf file "
                            "or on the Configurations page.".format(
                                input_item.get("account"), input_item["name"]
                            )
                        )
                        return

                # If auth_type is not present in account configuration,
                # then default auth_type will considered for data collection
                # Default auth_type = basic
                account_auth_type = account_details.get("auth_type", "basic")

                # Verify the list of required parameters based on the auth_type parameter
                if account_auth_type == "basic":
                    account_parameter = [
                        f for f in snow_basic_account_fields if f not in account_details
                    ]
                elif account_auth_type == "oauth":
                    account_parameter = [
                        f for f in snow_oauth_account_fields if f not in account_details
                    ]
                else:
                    error_msg = "Invalid value '{0}' of 'auth_type' parameter for account '{1}'".format(
                        account_details.get("auth_type"), input_item["account"]
                    )
                    # Logging an error message related to invalid 'auth_type' parameter configured
                    _LOGGER.error(error_msg)
                    return

                if len(account_parameter) > 0:
                    error_msg = (
                        "Found '{0}' parameter(s) missing for account '{1}'. To resume data collection, "
                        "fix the account configuration either from Configuration page of the Add-on or by "
                        "manual changes in splunk_ta_snow_account.conf.".format(
                            ", ".join(account_parameter), input_item["account"]
                        )
                    )
                    # Adding an error message related to missing required parameters for data collection
                    _LOGGER.error(error_msg)
                    return

                # Assign default value if disable_ssl_certificate_validation is missing
                if "disable_ssl_certificate_validation" not in account_details:
                    account_details["disable_ssl_certificate_validation"] = 0
                    _LOGGER.warning(
                        "Found 'disable_ssl_certificate_validation' parameter value missing for account '{}'."
                        " Using default value='False' to continue data collection.".format(
                            input_item["account"]
                        )
                    )

                if input_item.get("exclude", None):
                    excludes = input_item["exclude"].lower().split(",")
                    excludes = [ex.strip() for ex in excludes]
                else:
                    excludes = ()

                # Debug log for disable_ssl_certificate_validation
                _LOGGER.debug(
                    "'disable_ssl_certificate_validation' parameter has value {} for account {}".format(
                        account_details["disable_ssl_certificate_validation"],
                        input_item["account"],
                    )
                )

                # Aggregate all config-related parameters in one dictionary
                for key, value in account_info[input_item["account"]].items():
                    input_item[key] = input_item.get(key, value)

                input_item["auth_type"] = input_item.get("auth_type", account_auth_type)

                input_item.update(meta_configs)

                for key, value in service_now_conf["snow_default"].items():
                    input_item[key] = input_item.get(key, value)

                input_item.update(splunk_ta_snow_settings_conf["proxy"])

                input_item.update(splunk_ta_snow_settings_conf["logging"])

                stanza_configs.append(input_item)

            except Exception:
                _LOGGER.error("Error %s", traceback.format_exc())

            snow_data_collection_obj = Snow(input_item)
            _LOGGER.info(
                "Data collection starts for the input '{}'".format(
                    input_name.split("//")[1]
                )
            )
            snow_data_collection_obj.collect_data(
                table=input_item.get("table"),
                timefield=input_item.get("timefield", "sys_updated_on"),
                input_name=input_item.get("name"),
                host=input_item.get("host"),
                excludes=excludes,
                count=input_item.get("record_count", sc.DEFAULT_RECORD_LIMIT),
            )
            _LOGGER.info(
                "Data collection ends for the input '{}'".format(
                    input_name.split("//")[1]
                )
            )
        except Exception:
            _LOGGER.error("Error %s", traceback.format_exc())


if __name__ == "__main__":
    exit_code = SNOW().run(sys.argv)
    sys.exit(exit_code)
