#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

from datetime import datetime

import framework.log as log
from splunktaucclib.rest_handler.endpoint.validator import Validator

from snow import (  # isort: skip
    index_field_validation,
    special_character_validation,
    validate_combined_length,
)

APP_NAME = "Splunk_TA_snow"
_LOGGER = log.Logs().get_logger("main")
UI_FIELD_VALIDATION_MESSAGE = "For {}, values can only include lower-case letters, numbers, '$', '.' and '_' characters. Got the value: {}"  # noqa: E501
FIELD_TO_LABEL = {
    "id_field": "ID field",
    "timefield": "Time field of the table",
    "exclude": "Excluded properties",
    "include": "Included properties",
}


class DateValidator(Validator):
    """
    This class validates if the data passed for validation
     in input is in future.
    If so throws error in UI and logs
    """

    def __init__(self, *args, **kwargs):
        super(DateValidator, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        try:
            input_date = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
            now = datetime.utcnow()
            if input_date > now:
                self.put_msg("Start date should not be in future", True)
                _LOGGER.error(
                    "Start date of the input should not be in future, but got '{}'".format(
                        value
                    )
                )
                return False

        except ValueError:
            self.put_msg(
                "The provided date does not match format '%Y-%m-%d %H:%M:%S'", True
            )
            _LOGGER.error(
                "Start Date of the input should be in YYYY-MM-DD hh:mm:ss format, but got '{}'".format(
                    value
                )
            )
            return False
        return True


class IncludeFilterParameterValidator(Validator):
    """
    This class validates the 'include' field value and also
    validates that the combined length of Filter Parameters
    and Included Properties is not more than 1000 characters.
    """

    def __init__(self, *args, **kwargs):
        super(IncludeFilterParameterValidator, self).__init__(*args, **kwargs)

    def validate(self, value, data):

        length_of_url_parameters_combined = validate_combined_length(
            data.get("filter_data", ""), data.get("include", "")
        )
        if length_of_url_parameters_combined:
            error_message = (
                "The combined length of Filter Parameters and Included Properties is too long({})."
                "The maximum permissible length is 1000 characters."
            ).format(length_of_url_parameters_combined)
            self.put_msg(error_message, True)
            return False

        if data.get("include") and not special_character_validation(
            data.get("include")
        ):
            self.put_msg(
                UI_FIELD_VALIDATION_MESSAGE.format(
                    FIELD_TO_LABEL.get("include"), data.get("include")
                ),
                True,
            )
            return False
        return True


class IndexValidator(Validator):
    """
    This class validates index field value.
    If it contains unsupported characters or length, throws error in UI and logs
    """

    def __init__(self, *args, **kwargs):
        super(IndexValidator, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        res, error_log = index_field_validation(value)
        if not res:
            self.put_msg(error_log)
        return res


class SpecialValidator(Validator):
    def __init__(self, *args, **kwargs):
        # popping the name as it isn't required in Validator class
        self.name = kwargs.pop("name")
        super(SpecialValidator, self).__init__(*args, **kwargs)

    def validate(self, value, data):
        if not special_character_validation(value):
            self.put_msg(
                UI_FIELD_VALIDATION_MESSAGE.format(
                    FIELD_TO_LABEL.get(self.name, "<unknown field>"), value
                ),
                True,
            )
            return False
        return True
