#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test
import json
import os
import os.path as op
import snow_consts
from solnlib.modular_input import checkpointer, FileCheckpointer
from solnlib.splunkenv import make_splunkhome_path


class CheckpointHandler:
    """
    This class handles the file and kv checkpoint operations for
    ServiceNow modular inputs.
    """

    def __init__(self, collection_name, session_key, logger, **kwargs) -> None:
        self.collection_name = collection_name
        self.session_key = session_key
        self.logger = logger

        self.input_name = kwargs["input_name"]
        self.table = kwargs["table"]
        self.timefield = kwargs["timefield"]

        self.checkpoint_name = ".".join((self.input_name, self.table, self.timefield))
        self.checkpoint_dir = make_splunkhome_path(
            ["var", "lib", "splunk", "modinputs", "snow"]
        )
        self.kvstore_checkpointer = checkpointer.KVStoreCheckpointer(
            self.collection_name, self.session_key, snow_consts.APP_NAME
        )

    def get_kv_checkpoint(self):
        try:
            checkpoint_value = self.kvstore_checkpointer.get(self.checkpoint_name)
            return checkpoint_value
        except Exception as e:
            self.logger.error(
                "Error occurred while getting the value of checkpoint for input = {} : {}".format(
                    self.input_name, e
                )
            )
            raise e

    def update_kv_checkpoint(self, checkpoint_value):
        try:
            self.kvstore_checkpointer.update(self.checkpoint_name, checkpoint_value)
            self.logger.debug(
                "Successfully updated the value of checkpoint for input = {}".format(
                    self.input_name
                )
            )
        except Exception as e:
            self.logger.error(
                "Error occurred while updating the value of checkpoint for input = {} : {}".format(
                    self.input_name, e
                )
            )
            raise e

    def delete_kv_checkpoint(self):
        try:
            self.kvstore_checkpointer.delete(self.checkpoint_name)
            self.logger.info(
                "Successfully deleted the KV checkpoint for input = {}".format(
                    self.input_name
                )
            )
        except Exception as e:
            self.logger.error(
                "Error occured while deleting the checkpoint for input = {} : {}".format(
                    self.input_name, e
                )
            )
            raise e

    def check_for_kv_checkpoint(self):
        try:
            checkpoint_value = self.kvstore_checkpointer.get(self.checkpoint_name)
            if checkpoint_value:
                return True
        except Exception as e:
            self.logger.error(
                "Error occured while searching for kv checkpoint for input = {} : {}".format(
                    self.input_name, e
                )
            )
            raise e
        return False

    def check_for_file_checkpoint(self):
        try:
            checkpoint_name = ".".join((self.input_name, self.timefield))
            fname = op.join(self.checkpoint_dir, checkpoint_name)
            if op.exists(fname):
                with open(fname) as f:
                    checkpoint_value = json.load(f)
                if checkpoint_value:
                    return True
        except Exception as e:
            self.logger.error(
                "Error occured while checking for file checkpoint for input = {} : {}".format(
                    self.input_name, e
                )
            )
            raise e
        return False

    def get_file_checkpoint(self):
        try:
            checkpoint_name = ".".join((self.input_name, self.timefield))
            fname = op.join(self.checkpoint_dir, checkpoint_name)
            if op.exists(fname):
                with open(fname) as f:
                    checkpoint_value = json.load(f)
                if checkpoint_value:
                    return checkpoint_value
        except Exception as e:
            self.logger.error(
                "Error occured while getting file checkpoint for input = {} : {}".format(
                    self.input_name, e
                )
            )
            raise e
        return {}

    def delete_file_checkpoint(self):
        try:
            checkpoint_name = ".".join((self.input_name, self.timefield))
            fname = op.join(self.checkpoint_dir, checkpoint_name)
            if op.exists(fname):
                os.remove(fname)
            self.logger.info(
                "Successfully deleted file checkpoint for input = {}".format(
                    self.input_name
                )
            )
        except Exception as e:
            self.logger.error(
                "Error occured while deleting file checkpoint for input = {} : {}".format(
                    self.input_name, e
                )
            )
            raise e
