#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#


import import_declare_test  # isort: skip # noqa: F401

import logging

from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.rest_handler.admin_external import AdminExternalHandler

from splunk_ta_snow_account_validation import (  # isort: skip
    AccountValidation,
    RemoveRedundantParam,
    URLValidation,
)
from splunktaucclib.rest_handler.endpoint import (  # isort: skip
    RestModel,
    SingleModel,
    field,
    validator,
)

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        "endpoint", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "url", required=True, encrypted=False, default=None, validator=URLValidation()
    ),
    field.RestField(
        "record_count",
        required=False,
        encrypted=False,
        default=3000,
        validator=validator.Number(max_val=10000, min_val=1, is_int=True),
    ),
    field.RestField(
        "disable_ssl_certificate_validation",
        required=False,
        encrypted=False,
        default=0,
        validator=None,
    ),
    field.RestField(
        "username", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "password",
        required=False,
        encrypted=True,
        default=None,
        validator=AccountValidation(),
    ),
    field.RestField(
        "client_id", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "client_secret",
        required=False,
        encrypted=True,
        default=None,
        validator=RemoveRedundantParam(),
    ),
    field.RestField(
        "redirect_url", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "access_token", required=False, encrypted=True, default=None, validator=None
    ),
    field.RestField(
        "refresh_token", required=False, encrypted=True, default=None, validator=None
    ),
    field.RestField(
        "instance_url", required=False, encrypted=False, default=None, validator=None
    ),
    field.RestField(
        "auth_type", required=False, encrypted=False, default=None, validator=None
    ),
]
model = RestModel(fields, name=None)


endpoint = SingleModel("splunk_ta_snow_account", model, config_name="account")


if __name__ == "__main__":
    logging.getLogger().addHandler(logging.NullHandler())
    admin_external.handle(
        endpoint,
        handler=AdminExternalHandler,
    )
