================================================
Overview
================================================

This app provides a mechanism for pulling information from websites.



================================================
Warning
================================================

Some websites disallow web-scraping in the terms of use. Make sure to check the terms of use or get permission if you do not own the website that you are obtaining information from.



================================================
Configuring Splunk
================================================

This app exposes a new input type that can be configured in the Splunk Manager. To configure it, create a new input in the Manager under Data inputs � Web-pages.



================================================
Getting Support
================================================

Go to the following website if you need support:

     http://splunk-base.splunk.com/apps/1818/answers/

You can access the source-code and get technical details about the app at:

     https://github.com/LukeMurphey/splunk-web-input



================================================
Change History
================================================

+---------+------------------------------------------------------------------------------------------------------------------+
| Version |  Changes                                                                                                         |
+---------+------------------------------------------------------------------------------------------------------------------+
| 0.5     | Initial release                                                                                                  |
|---------|------------------------------------------------------------------------------------------------------------------|
| 0.6     | Switched to multi-value output of matches and added transform for parsing match field                            |
|         | Fixed exception that could happen if the web-page was not available                                              |
|         | Put authentication fields on a separate location on the manager page                                             |
|---------|------------------------------------------------------------------------------------------------------------------|
| 0.7     | Fixed crash that would occur if the connection timed-out                                                         |
|---------|------------------------------------------------------------------------------------------------------------------|
| 0.8     | Fixed issue where content did not get encoded correctly                                                          |
|---------|------------------------------------------------------------------------------------------------------------------|
| 0.9     | Fixed issue where not all matches were returned                                                                  |
|         | Added preview dialog to modular input page                                                                       |
|         | Added raw_match_count to output which counts CSS matches, even they included no text                             |
|         | Fixed incompatibility with other apps that also import the modular_input base class                              |
|         | Fixed issue where entering and then clearing the sourcetype causes an error                                      |
|         | Added ability to specify attributes that should be used for the field names                                      |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0     | Added ability to use a proxy server                                                                              |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0.1   | Fixed issue where preview did not work                                                                           |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0.2   | Fixed issue where the input would:                                                                               |
|         |    sometimes fail due to exception thrown from sleep() being interrupted                                         |
|         |    sometimes fail due to splunkd connection failure                                                              |
|         |    ignore the host field that was set on the configuration page                                                  |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0.3   | Fixed issue where the input would not stay on the interval because it included processing time in the interval   |
|         | Fixed issue where the modular input logs were not sourcetyped correctly                                          |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0.4   | Enhanced logging for when interval gap is too large and when checkpoint file could not be found                  |
|         | Fixed issue where some files could not be parsed because lxml won't parsed correctly encoded files in some cases |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0.5   | Fixed issue where web input controller used the incorrect logger name                                            |
|         | Fixed issue where you could not select the sourcetype correctly in some cases                                    |
|         | Added a search command for performing web scrapes from the search page                                           |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.0.6   | Added ability to specify the user-agent string                                                                   |
+---------+------------------------------------------------------------------------------------------------------------------+
