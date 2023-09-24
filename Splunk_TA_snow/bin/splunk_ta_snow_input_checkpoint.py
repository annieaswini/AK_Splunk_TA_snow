#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip # noqa: F401
import traceback

import splunk.admin as admin
from framework import state_store as ss
from solnlib import log

import snow_checkpoint
import snow_consts

log.Logs.set_context()
_LOGGER = log.Logs().get_logger("ta_snow_data_input_checkpoint")


class CheckpointRestHandler(admin.MConfigHandler):
    def setup(self):
        self.supportedArgs.addReqArg("input_name")
        return

    @staticmethod
    def get_session_key(self):
        return self.getSessionKey()

    """
    This handler is to get checkpoint of data input
    It takes 'input_name' as caller args and
    Returns the confInfo dict object in response.
    """

    def handleList(self, confInfo):
        try:
            _LOGGER.debug("In checkpoint handler to get checkpoint of data input")
            # # Get args parameters from the request
            _LOGGER.debug("self.callerArgs.data: {}".format(self.callerArgs.data))
            checkpoint_name = self.callerArgs.data["input_name"][0]
            session_key = self.get_session_key(self)

            input_name, table, timefield = checkpoint_name.split(".")

            checkpoint_handler = snow_checkpoint.CheckpointHandler(
                collection_name=snow_consts.CHECKPOINT_COLLECTION_NAME,
                session_key=session_key,
                logger=_LOGGER,
                input_name=input_name,
                table=table,
                timefield=timefield or "sys_updated_on",
            )

            is_file_chkpt_exist = checkpoint_handler.check_for_file_checkpoint()
            is_kv_chkpt_exist = checkpoint_handler.check_for_kv_checkpoint()

            if is_file_chkpt_exist or is_kv_chkpt_exist:
                _LOGGER.info(
                    "Found checkpoint for input = {}, table = {}, timefield = {}".format(
                        input_name, table, timefield
                    )
                )
                confInfo["token"]["checkpoint_exist"] = True
            else:
                _LOGGER.info(
                    "Checkpoint not found for input = {}, table = {}, timefield = {}".format(
                        input_name, table, timefield
                    )
                )
                confInfo["token"]["checkpoint_exist"] = False

        except Exception:
            _LOGGER.error("Error {}".format(traceback.format_exc()))
        return


if __name__ == "__main__":
    admin.init(CheckpointRestHandler, admin.CONTEXT_APP_AND_USER)
