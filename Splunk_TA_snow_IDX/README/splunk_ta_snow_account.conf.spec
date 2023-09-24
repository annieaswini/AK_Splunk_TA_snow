##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

[<name>]
url = <string> ServiceNow URL, for example, https://myaccount.service-now.com.
username = <string> ServiceNow account username.
password = <string> ServiceNow account password.
endpoint = <string> Service instance URL for getting tokens.
client_id = <string> Client Id  for ServiceNow Oauth.
client_secret = <string> Client Secret  for ServiceNow Oauth.
access_token = <string> Encrypted access token.
refresh_token = <string> Ecrypted refresh token.
auth_type = <string> Type of authentication used.
record_count = <integer> Number of records to be fetched in each database table call.
disable_ssl_certificate_validation = <bool> Whether to disable SSL certificate validation or not.
