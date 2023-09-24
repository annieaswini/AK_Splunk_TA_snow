##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

[snow_event]
param.account = <list> Mention Account(s). Should be a comma-delimited list. It's a required parameter.
param.node = <string> Node. It's a required parameter.
param.type = <string> Type. It's a required parameter.
param.resource = <string> Resource. It's a required parameter.
param.severity = <string> Severity. It's a required parameter.
param.description = <string> Description.
param.ci_identifier = <string> CI identifier.
param.additional_info = <string> Additional Info.
param.custom_fields = <string> Custom Fields.
python.version = {default|python|python2|python3}
* For Splunk 8.0.x and Python scripts only, selects which Python version to use.
* Either "default" or "python" select the system-wide default Python version.
* Optional.
* Default: not set; uses the system-wide Python version.

[snow_incident]
param.account = <string> Select Account. It's a required parameter.
param.state = <string> State.
param.host = <string> Host name.
param.scripted_endpoint = <string> Resource path to create incident at.
param.configuration_item = <string> Configuration Item.
param.contact_type = <string> Contact Type. It's a required parameter.
param.assignment_group = <string> Assignment Group.
param.category = <string> Category. It's a required parameter.
param.subcategory = <string> Subcategory.
param.impact = <number> Impact
param.urgency = <number> Urgency
param.priority = <number> Priority
param.short_description = <string> Short Description. It's a required parameter.
param.correlation_id = <string> Correlation ID.
param.splunk_url = <link> splunk_url for Splunk Drilldown
param.custom_fields = <string> Custom Fields.
python.version = {default|python|python2|python3}
* For Splunk 8.0.x and Python scripts only, selects which Python version to use.
* Either "default" or "python" select the system-wide default Python version.
* Optional.
* Default: not set; uses the system-wide Python version.
