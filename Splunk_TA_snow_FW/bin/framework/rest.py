#
# SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
#
#

import import_declare_test  # isort: skip   # noqa: F401
import json
import os.path as op
import sys
import urllib.parse
from traceback import format_exc

import requests

sys.path.insert(0, op.dirname(op.dirname(op.abspath(__file__))))

import framework.log as log  # noqa: E402
import framework.ta_consts as c  # noqa: E402
import framework.utils as utils  # noqa: E402

_LOGGER = log.Logs().get_logger(c.ta_util)


def splunkd_request(
    splunkd_uri, session_key, method="GET", headers=None, data=None, timeout=30, retry=1
):
    """
    @return: requests.Response and content
    """

    headers = headers if headers is not None else {}
    headers["Authorization"] = "Splunk {0}".format(session_key)
    content_type = headers.get("Content-Type")
    if not content_type:
        content_type = headers.get("content-type")

    if not content_type:
        content_type = "application/x-www-form-urlencoded"
        headers["Content-Type"] = content_type

    if data is not None:
        if content_type == "application/json":
            data = json.dumps(data)
        else:
            data = urllib.parse.urlencode(data)

    msg_temp = "Failed to send rest request=%s, errcode=%s, reason=%s"
    resp, content = None, None
    for _ in range(retry):
        try:
            # semgrep ignore reason:
            # 1) we have custom handling for unsuccessful HTTP status codes
            # 2) Since it is in internal Splunkd call, SSL verification is turned off
            resp = requests.request(  # nosemgrep: python.requests.security.disabled-cert-validation.disabled-cert-validation, python.requests.best-practice.use-raise-for-status.use-raise-for-status, gitlab.bandit.B501, contrib.dlint.dlint-equivalent.insecure-requests-use  # noqa: E501
                method,
                splunkd_uri,
                headers=headers,
                data=data,
                verify=False,
                timeout=timeout,
            )
            content = resp.content
        except Exception:
            _LOGGER.error(msg_temp, splunkd_uri, "unknown", format_exc())
        else:
            if resp.status_code not in (200, 201):
                _LOGGER.error(
                    msg_temp, splunkd_uri, resp.status_code, code_to_msg(resp, content)
                )
            else:
                return resp, content
    else:
        return resp, content


def code_to_msg(resp, content):
    code_msg_tbl = {
        400: "Request error. reason={}".format(content),
        401: "Authentication failure, invalid access credentials.",
        402: "In-use license disables this feature.",
        403: "Insufficient permission.",
        404: "Requested endpoint does not exist.",
        409: "Invalid operation for this endpoint. reason={}".format(content),
        500: "Unspecified internal server error. reason={}".format(content),
        503: (
            "Feature is disabled in the configuration file. "
            "reason={}".format(content)
        ),
    }

    return code_msg_tbl.get(resp.status_code, content)


def build_proxy_info(config):
    """
    @config: dict like, proxy and account information are in the following
             format {
                 "username": xx,
                 "password": yy,
                 "proxy_url": zz,
                 "proxy_port": aa,
                 "proxy_username": bb,
                 "proxy_password": cc,
                 "proxy_type": http,sock4,sock5,
                 "proxy_rdns": 0 or 1,
             }
    @return: Dict of proxy information
    """

    # Verifying if proxy is enabled or not
    if not utils.is_true(config.get("proxy_enabled")):
        return None

    # Assign value to proxy_type parameter
    if config.get("proxy_type") in ("http", "socks5"):
        proxy_type = config.get("proxy_type")

    # if proxy_type is None assign default value to it
    elif not config.get("proxy_type"):
        proxy_type = "http"
        _LOGGER.warn(
            "Value of 'proxy_type' parameter missing. Using default value='http' to continue data collection."
        )
    # Exception if proxy_type has unexpected value
    else:
        raise Exception(
            "Got unexpected value {} of proxy_type parameter. Supported values of proxy_type parameter are "
            "http, socks5".format(config.get("proxy_type"))
        )

    rdns = utils.is_true(config.get("proxy_rdns"))

    # socks5 causes the DNS resolution to happen on the client
    # socks5h causes the DNS resolution to happen on the proxy server
    if rdns and proxy_type == "socks5":
        proxy_type = "socks5h"

    if config.get("proxy_url") and config.get("proxy_port"):
        if config.get("proxy_username") and config.get("proxy_password"):
            proxy_info = {
                "http": (
                    f'{proxy_type}://{config["proxy_username"]}:{config["proxy_password"]}'
                    f'@{config["proxy_url"]}:{int(config["proxy_port"])}'
                )
            }
        else:
            proxy_info = {
                "http": f'{proxy_type}://{config["proxy_url"]}:{int(config["proxy_port"])}'
            }
        proxy_info["https"] = proxy_info["http"]

    return proxy_info
