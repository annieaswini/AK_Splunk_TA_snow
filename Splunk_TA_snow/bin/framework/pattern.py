#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

"""
Copyright (C) 2018 Splunk Inc. All Rights Reserved.

Commonly used design partten for python user, includes:
  - singleton (Decorator function used to build singleton)
"""
from functools import wraps


def singleton(class_):
    """
    Singleton decoorator function.
    """
    instances = {}

    @wraps(class_)
    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]

    return getinstance


class Singleton(type):
    """
    Singleton meta class
    """

    _instances = {}  # type: ignore

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
            print(cls)
        return cls._instances[cls]
