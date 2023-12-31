##
## SPDX-FileCopyrightText: 2021 Splunk, Inc. <sales@splunk.com>
## SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

[snow_default]
priority = <integer> Prioritize the inputs for data collection. Value should be between 0-10. 0 is minimum and 10 is maximum.
display_value = <all|false> Data retrieval operation when grouping by reference or choice fields. For display_value=false the query will return the actual values from the database. For display_value=all the query will return both actual and display values the from the database.
