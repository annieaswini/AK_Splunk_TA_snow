#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#


import import_declare_test  # isort: skip # noqa: F401

import logging

from splunk_ta_snow_account_validation import ProxyValidation
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

from splunktaucclib.rest_handler.endpoint import (  # isort: skip
    MultipleModel,
    RestModel,
    field,
    validator,
)

util.remove_http_proxy_env_vars()


fields_proxy = [
    field.RestField(
        "proxy_enabled", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "proxy_url",
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            max_len=4096,
            min_len=0,
        ),
    ),
    field.RestField(
        "proxy_port",
        required=True,
        encrypted=False,
        default=None,
        validator=validator.Number(max_val=65535, min_val=1, is_int=True),
    ),
    field.RestField(
        "proxy_username",
        required=False,
        encrypted=False,
        default=None,
        validator=ProxyValidation(),
    ),
    field.RestField(
        "proxy_password",
        required=False,
        encrypted=True,
        default=None,
        validator=ProxyValidation(),
    ),
    field.RestField(
        "proxy_rdns", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "proxy_type", required=True, encrypted=False, default="http", validator=None
    ),
]
model_proxy = RestModel(fields_proxy, name="proxy")


fields_logging = [
    field.RestField(
        "loglevel", required=True, encrypted=False, default="INFO", validator=None
    )
]
model_logging = RestModel(fields_logging, name="logging")

fields_additional_parameters = [
    field.RestField(
        "create_incident_on_zero_results",
        required=False,
        encrypted=False,
        default=False,
        validator=None,
    ),
    field.RestField(
        "ca_certs_path",
        required=False,
        encrypted=False,
        default="",
        validator=None,
    ),
]
model_additional_parameters = RestModel(
    fields_additional_parameters, name="additional_parameters"
)

field_api_selection = [
    field.RestField(
        "selected_api",
        required=True,
        encrypted=False,
        default="table_api",
        validator=None,
    )
]
model_api_selection = RestModel(field_api_selection, name="api_selection")

endpoint = MultipleModel(
    "splunk_ta_snow_settings",
    models=[
        model_proxy,
        model_logging,
        model_additional_parameters,
        model_api_selection,
    ],
)


class SettingsHandler(AdminExternalHandler):
    """
    Manage Settings Details.
    """

    def __init__(self, *args, **kwargs):
        AdminExternalHandler.__init__(self, *args, **kwargs)

    def handleList(self, confInfo):
        AdminExternalHandler.handleList(self, confInfo)
        # Logic to make proxy_password empty in the UI
        if confInfo.get("proxy"):
            if confInfo["proxy"].get("proxy_password"):
                confInfo["proxy"]["proxy_password"] = ""


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=SettingsHandler,
    )
