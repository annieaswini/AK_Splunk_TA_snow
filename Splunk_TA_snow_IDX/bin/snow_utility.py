#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#
import logging
import traceback
import requests
from typing import Any
import json

import snow_consts
import snow_checkpoint
from solnlib import conf_manager


def split_string_to_dict(event_data_dict: dict, event_field: str) -> dict:
    """
    :param event_data_dict: a dictionary which requires to be updated.
    :param event_field: a string which is double pipe delimited and needs to be split into a KV pair
    :return: the updated dictionary formed by splitting the `event_field`
    """
    all_fields = event_field.split(snow_consts.FIELD_SEPARATOR)
    for each_field in all_fields:
        field_kv_list = each_field.split("=", 1)
        # Verifying that fields are in key value format and key is not null
        if len(field_kv_list) == 2 and field_kv_list[0].strip():
            event_data_dict.update({field_kv_list[0].strip(): field_kv_list[1].strip()})
        else:
            msg = "The field '{}' is not in key value format. Expected format: key1=value1||key2=value2.".format(
                str(each_field)
            )
            return {"Error Message": msg}
    return event_data_dict


def get_selected_api(session_key, logger: logging.Logger) -> str:
    """
    :param `session_key`: Session Key to read the conf file data
    :param `logger`: Object of logging.Logger
    :return `selected_api`: String ("table_api" or "import_set_api")
    """
    conf_name = snow_consts.SETTINGS_CONF_FILE
    # "Table API" will be used in case of any error reading "splunk_ta_snow_settings.conf" file
    selected_api = "table_api"
    try:
        cfm = conf_manager.ConfManager(
            session_key,
            snow_consts.APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-{}".format(
                snow_consts.APP_NAME, conf_name
            ),
        )
        selected_api = (
            cfm.get_conf(conf_name, refresh=True)
            .get("api_selection")
            .get("selected_api")
            or ""
        ).strip()

    except Exception:
        msg = f"Error while fetching selected_api value from '{conf_name}' conf. Traceback: {traceback.format_exc()}"
        logger.error(msg)

    if selected_api not in ["table_api", "import_set_api"]:
        selected_api = "table_api"

    return selected_api


def migrate_duration_to_interval(
    input_name: str, input_item: dict, meta_configs: dict, logger: Any
) -> None:
    """
    :param `input_name`: Name of the snow modular input
    :param `input_item`: Dictionary containing input details
    :param `meta_configs`: Dictionary containing splunk session details
    :param `logger`: Logger object for logging
    :return None:
    """

    logger.info(
        "Proceeding to migrate duration field to interval field for input = {}".format(
            input_name
        )
    )

    try:
        snow_input_name = input_name.split("://")[1]
        splunk_inputs_endpoint = "{}/servicesNS/nobody/{}/data/inputs/snow/{}".format(
            meta_configs["server_uri"], snow_consts.APP_NAME, snow_input_name
        )
        headers = {"Authorization": "Bearer {}".format(meta_configs["session_key"])}

        try:
            duration = int(input_item["duration"])
        except ValueError:
            logger.warning(
                "DURATION field value should be an integer. Migration from DURATION field to INTERVAL field cannot be performed for input {}. INTERVAL of {} seconds will be used for the input. If you keep on seeing this error, remediation step is to edit the input and set the interval from the UI for once.".format(
                    input_name, input_item["interval"]
                )
            )
            return

        migration_data = {
            "interval": duration,
            "duration": "Deprecated - Please use the interval field instead",
        }

        # Note : If the below POST request to Splunk data/inputs endpoint is successful,
        # the input will be reinvoked and no further code in the function will be executed.
        response = requests.post(
            url=splunk_inputs_endpoint,
            headers=headers,
            data=migration_data,
            verify=False,
        )

        if response.status_code not in (200, 201):
            logger.error(
                "Migration from duration field to interval field was NOT successful. Returned status code = {}. Reason for failure = {}".format(
                    response.status_code, response.text
                )
            )

    except Exception:
        logger.error(
            "Some error occurred during migration from duration field to interval field for input {}. Traceback = {}".format(
                input_name, traceback.format_exc()
            )
        )
        logger.warning(
            "INTERVAL of {} seconds will be used for input {} due to the DURATION field migration failing. The migration will be attempted again in 60 seconds automatically if input is enabled. If you keep on seeing this error, remediation step is to edit the input and set the interval from the UI for once.".format(
                input_item["interval"], input_name
            )
        )


def is_checkpoint_migrated_to_kv(
    input_name: str, input_item: dict, meta_configs: dict, logger: logging.Logger
) -> bool:
    """
    :param `input_name`: Name of the snow modular input
    :param `input_item`: Dictionary containing input details
    :param `meta_configs`: Dictionary containing splunk session details
    :param `logger`: Logger object for logging
    :return bool:
    """
    try:
        input_name = input_name.split("://")[1]

        checkpoint_handler = snow_checkpoint.CheckpointHandler(
            collection_name=snow_consts.CHECKPOINT_COLLECTION_NAME,
            session_key=meta_configs["session_key"],
            logger=logger,
            input_name=input_name,
            table=input_item["table"],
            timefield=(input_item.get("timefield") or "sys_updated_on"),
        )

        file_checkpoint_exist = checkpoint_handler.check_for_file_checkpoint()
        kv_checkpoint_exist = checkpoint_handler.check_for_kv_checkpoint()
        if file_checkpoint_exist and not kv_checkpoint_exist:
            logger.info(
                "Checkpoint is not migrated from file to kv for input {}".format(
                    input_name
                )
            )
            return False

    except Exception as e:
        logger.error(
            "Some error occurred while checking if checkpoint is migrated from file to kv for input {}. Traceback = {}".format(
                input_name, traceback.format_exc()
            )
        )
        raise e
    return True


def migrate_file_to_kv_checkpoint(
    input_name: str, input_item: dict, meta_configs: dict, logger: logging.Logger
) -> bool:
    """
    :param `input_name`: Name of the snow modular input
    :param `input_item`: Dictionary containing input details
    :param `meta_configs`: Dictionary containing splunk session details
    :param `logger`: Logger object for logging
    :return None:
    """
    try:
        input_name = input_name.split("://")[1]

        checkpoint_handler = snow_checkpoint.CheckpointHandler(
            collection_name=snow_consts.CHECKPOINT_COLLECTION_NAME,
            session_key=meta_configs["session_key"],
            logger=logger,
            input_name=input_name,
            table=input_item["table"],
            timefield=(input_item.get("timefield") or "sys_updated_on"),
        )

        logger.info(
            "Proceeding to migrate file to kv checkpoint for input {}.".format(
                input_name
            )
        )
        # Migrate from file to kv
        checkpoint_value = checkpoint_handler.get_file_checkpoint()
        checkpoint_handler.update_kv_checkpoint(checkpoint_value)
        checkpoint_handler.delete_file_checkpoint()

        logger.info(
            "Checkpoint migrated successfully from file to kv for input {} with value {}".format(
                input_name, json.dumps(checkpoint_value)
            )
        )
        return True
    except Exception:
        logger.error(
            "Some error occurred while migrating file to kv checkpoint for input {}. Traceback = {}".format(
                input_name, traceback.format_exc()
            )
        )
        return False
