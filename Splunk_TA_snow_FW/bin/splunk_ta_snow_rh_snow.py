#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#


import import_declare_test  # isort: skip # noqa: F401

import logging
from datetime import datetime, timedelta

import framework.log as log
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

import snow_checkpoint
import snow_consts
from splunk_ta_snow_input_validation import (  # isort: skip
    DateValidator,
    IncludeFilterParameterValidator,
    IndexValidator,
    SpecialValidator,
)
from splunktaucclib.rest_handler.endpoint import (  # isort: skip
    DataInputModel,
    RestModel,
    field,
    validator,
)

util.remove_http_proxy_env_vars()
_LOGGER = log.Logs().get_logger("main")

fields = [
    field.RestField(
        "account", required=True, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "duration",
        required=False,
        encrypted=False,
        default="Deprecated - Please use the interval field instead",
    ),
    field.RestField(
        "interval",
        required=True,
        encrypted=False,
        default=60,
        validator=validator.Number(
            max_val=31536000,
            min_val=1,
        ),
    ),
    field.RestField(
        "table", required=True, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "include",
        required=False,
        encrypted=False,
        default=None,
        validator=IncludeFilterParameterValidator(),
    ),
    field.RestField(
        "exclude",
        required=False,
        encrypted=False,
        default=None,
        validator=SpecialValidator(name="exclude"),
    ),
    field.RestField(
        "timefield",
        required=False,
        encrypted=False,
        default="sys_updated_on",
        validator=SpecialValidator(name="timefield"),
    ),
    field.RestField(
        "reuse_checkpoint",
        required=False,
        encrypted=False,
        default="yes",
        validator=None,
    ),
    field.RestField(
        "since_when",
        required=False,
        encrypted=False,
        default=None,
        validator=DateValidator(),
    ),
    field.RestField(
        "id_field",
        required=False,
        encrypted=False,
        default="sys_id",
        validator=SpecialValidator(name="id_field"),
    ),
    field.RestField(
        "filter_data",
        required=False,
        encrypted=False,
        default=None,
    ),
    field.RestField("disabled", required=False, validator=None),
    field.RestField(
        "index",
        required=True,
        encrypted=False,
        default="default",
        validator=IndexValidator(),
    ),
]
model = RestModel(fields, name=None)


endpoint = DataInputModel(
    "snow",
    model,
)


class SnowHandler(AdminExternalHandler):
    """
    Manage Snow Data Input Details.
    """

    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    @staticmethod
    def get_session_key(self):
        return self.getSessionKey()

    def deleteCheckpoint(self, input_name, table, timefield):
        try:
            session_key = self.get_session_key(self)

            checkpoint_handler = snow_checkpoint.CheckpointHandler(
                collection_name=snow_consts.CHECKPOINT_COLLECTION_NAME,
                session_key=session_key,
                logger=_LOGGER,
                input_name=input_name,
                table=table,
                timefield=timefield,
            )

            if checkpoint_handler.check_for_file_checkpoint():
                checkpoint_handler.delete_file_checkpoint()
            if checkpoint_handler.check_for_kv_checkpoint():
                checkpoint_handler.delete_kv_checkpoint()
        except Exception:
            # Providing a customer friendly error message in UI instead of a traceback.
            # The detailed traceback can be seen in add-on logs.
            raise Exception("Failed to delete checkpoint for the input.")

    def checkReuseCheckpoint(self):
        # Check the reuse_checkpoint field. If it's value is 'no', delete it's checkpoint if present.
        if self.payload.get("reuse_checkpoint") == "no":
            input_name = self.callerArgs.id
            timefield = self.payload.get("timefield") or "sys_updated_on"
            table = self.payload.get("table")
            self.deleteCheckpoint(input_name, table, timefield)

        if "reuse_checkpoint" in self.payload:
            del self.payload["reuse_checkpoint"]

    def checkSinceWhen(self):
        now = datetime.utcnow() - timedelta(7)
        # Check if since_when field is empty. If so, set its default value to one week ago so that it reflects on UI.
        if not self.payload.get("since_when"):
            self.payload["since_when"] = datetime.strftime(now, "%Y-%m-%d %H:%M:%S")

    def handleCreate(self, confInfo):
        self.checkReuseCheckpoint()
        self.checkSinceWhen()

        AdminExternalHandler.handleCreate(self, confInfo)

    def handleEdit(self, confInfo):
        self.checkReuseCheckpoint()
        self.checkSinceWhen()

        # to handle the editting of inputs which are in disabled state and not yet migrated.
        self.payload["duration"] = "Deprecated - Please use the interval field instead"

        AdminExternalHandler.handleEdit(self, confInfo)

    def handleList(self, confInfo):
        AdminExternalHandler.handleList(self, confInfo)

        # If migration is not yet done, display duration field value instead of interval on the inputs page.
        for _, input_stanza_value in list(confInfo.items()):
            if input_stanza_value.get("duration"):
                if (
                    input_stanza_value["duration"]
                    != "Deprecated - Please use the interval field instead"
                ):
                    try:
                        duration = int(input_stanza_value["duration"])
                        input_stanza_value["interval"] = duration
                    except ValueError:
                        # do not show duration in UI if it is not an integer
                        pass


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=SnowHandler,
    )
