#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import datetime
import os
import os.path as op
import traceback
import urllib.parse

import snow_consts
from solnlib import conf_manager

# semgrep ignore reason: the escape function is not vulnerable so defusedxml does not have implementation for it


def make_splunkhome_path(parts):
    """
    @parts: path relative to splunk home
    """

    home = os.environ.get("SPLUNK_HOME", ".")
    fullpath = op.normpath(op.join(home, *parts))
    return fullpath


def get_splunk_bin():
    if os.name == "nt":
        splunk_bin = "splunk.exe"
    else:
        splunk_bin = "splunk"
    return make_splunkhome_path(("bin", splunk_bin))


def get_appname_from_path(absolute_path):
    parts = absolute_path.split(op.sep)
    parts.reverse()
    try:
        idx = parts.index("apps")
    except ValueError:
        return None
    else:
        try:
            if parts[idx + 1] == "etc":
                return parts[idx - 1]
            return None
        except IndexError:
            return None


def datetime_to_seconds(dt):
    epoch_time = datetime.datetime.utcfromtimestamp(0)
    return (dt - epoch_time).total_seconds()


def is_true(val):
    value = str(val).strip().upper()
    if value in ("1", "TRUE", "T", "Y", "YES"):
        return True
    return False


def is_false(val):
    value = str(val).strip().upper()
    if value in ("0", "FALSE", "F", "N", "NO", "NONE", ""):
        return True
    return False


def remove_http_proxy_env_vars():
    for k in ("http_proxy", "https_proxy"):
        if k in os.environ:
            del os.environ[k]
        elif k.upper() in os.environ:
            del os.environ[k.upper()]


def forked_saxutils_escape(data: str, entities={}) -> str:
    """Escape &, <, and > in a string of `data`.
    You can escape other strings of data by passing a dictionary as
    the optional `entities` parameter.  The keys and values must all be
    strings; each key will be replaced with its corresponding value.
    """

    def __dict_replace(s, d):
        """Replace substrings of a string using a dictionary."""
        for key, value in d.items():
            s = s.replace(key, value)
        return s

    # must do ampersand first
    data = data.replace("&", "&amp;")
    data = data.replace(">", "&gt;")
    data = data.replace("<", "&lt;")
    if entities:
        data = __dict_replace(data, entities)
    return data


def escape_cdata(data):
    data = data.encode("utf-8", errors="xmlcharrefreplace").decode("utf-8")
    data = forked_saxutils_escape(data)
    return data


def setup_logging(log_name, level_name="INFO", refresh=False):
    """
    @log_name: which logger
    @level_name: log level, a string
    """
    import logging
    import logging.handlers as handlers

    level_name = level_name.upper() if level_name else "INFO"
    loglevel_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARN": logging.WARN,
        "ERROR": logging.ERROR,
        "FATAL": logging.FATAL,
    }

    if level_name in loglevel_map:
        loglevel = loglevel_map[level_name]
    else:
        loglevel = logging.INFO

    logfile = make_splunkhome_path(["var", "log", "splunk", "%s.log" % log_name])
    logger = logging.getLogger(log_name)

    handler_exists = any([True for h in logger.handlers if h.baseFilename == logfile])
    if not handler_exists:
        file_handler = handlers.RotatingFileHandler(
            logfile, mode="a", maxBytes=104857600, backupCount=5
        )
        fmt_str = "%(asctime)s %(levelname)s %(thread)d - %(message)s"
        formatter = logging.Formatter(fmt_str)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.setLevel(loglevel)
        logger.propagate = False

    if refresh:
        logger.setLevel(loglevel)

    return logger


def get_sslconfig(config, session_key, logger):
    conf_name = "splunk_ta_snow_settings"
    session_key = urllib.parse.unquote(session_key.encode("ascii").decode("ascii"))
    session_key = session_key.encode().decode("utf-8")
    try:
        # Default value will be used for ca_certs_path and
        # disable_ssl_certificate_validation if there is any error
        sslconfig = False
        disable_ssl_certificate_validation = False
        ca_certs_path = ""
        disable_ssl_certificate_validation = is_true(
            config.get("disable_ssl_certificate_validation")
        )
        cfm = conf_manager.ConfManager(
            session_key,
            snow_consts.APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-{}".format(
                snow_consts.APP_NAME, conf_name
            ),
        )
        ca_certs_path = (
            cfm.get_conf(conf_name, refresh=True)
            .get("additional_parameters")
            .get("ca_certs_path")
            or ""
        ).strip()

    except Exception:
        msg = f"Error while fetching ca_certs_path from '{conf_name}' conf. Traceback: {traceback.format_exc()}"
        logger.error(msg)

    if disable_ssl_certificate_validation is False:
        if ca_certs_path != "":
            sslconfig = ca_certs_path
        else:
            sslconfig = True

    return sslconfig
