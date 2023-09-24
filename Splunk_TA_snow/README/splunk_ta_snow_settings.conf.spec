##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

[proxy]
proxy_enabled = <bool> Enable or disable proxy.
proxy_url = <string> Proxy URL.
proxy_port = <integer> Port for configuring proxy.
proxy_username = <string> Username for configuring proxy.
proxy_password = <string> Password for configuring proxy.
proxy_rdns = <bool> Remote DNS resolution.
proxy_type = <string> Proxy type (http, socks5).

[logging]
loglevel = <string> Select log level.

[additional_parameters]
create_incident_on_zero_results = <bool> Specifies whether to create incident on 0 search results or not.
ca_certs_path = <string> Custom path to CA certificate

[filter_parameter_migration]
has_migrated = [0|1] Whether input's filter_parameter has been migrated or not (for > v7.1.1).

[api_selection]
selected_api = [table_api|import_set_api] Select type of API to use while creating incident in ServiceNow
