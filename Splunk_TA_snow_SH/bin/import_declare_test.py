#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import os
import sys

sys.path.insert(
    0,
    os.path.sep.join(
        [os.path.dirname(os.path.realpath(os.path.dirname(__file__))), "lib"]
    ),
)

import http  # noqa: E402
import queue  # noqa: E402

assert (  # nosemgrep: gitlab.bandit.B101 - additional check for expected imports
    "Splunk_TA_snow" not in http.__file__
)
assert (  # nosemgrep: gitlab.bandit.B101 - additional check for expected imports
    "Splunk_TA_snow" not in queue.__file__
)
