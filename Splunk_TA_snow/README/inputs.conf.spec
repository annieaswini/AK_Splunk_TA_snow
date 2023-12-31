##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

[snow://<name>]
account = <string> Name of the account that would be used to get data.
interval = <integer> Collection interval for this table (in seconds).
duration = <integer> Deprecated - Please use the interval field instead
table = <string> Input name for which data will be collected.
exclude = <list> Properties to be excluded of the database table (comma separated).
include = <list> Properties to be included of the database table (comma separated). 'timefield' & 'id_field' will be added by default.
timefield = <string> Time field of the database table (Default is 'sys_updated_on').
reuse_checkpoint = <bool> Whether to use existing data input or not.
since_when = <string> The datetime after which to query and index records, in this format: "YYYY-MM-DD hh:mm:ss" (Default is one week ago).
id_field = <string> Field which uniquely identifies each row in this table (Default is 'sys_id').
filter_data = <list> Provide filters in key-value pairs for indexing only selected data from the table eg. key1=value1&key2=value2|key3=value3 (Use '&' for AND filter and '|' for OR filter. By default, no filter will be applied).

[snow]
python.version = {default|python|python2|python3}
* For Splunk 8.0.x and Python scripts only, selects which Python version to use.
* Either "default" or "python" select the system-wide default Python version.
* Optional.
* Default: not set; uses the system-wide Python version.
