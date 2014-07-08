================================================
Overview
================================================

This app provides a mechanism for pulling information from websites.



================================================
Configuring Splunk
================================================

This app exposes a new input type that can be configured in the Splunk Manager. To configure it, create a new input in the Manager under Data inputs È Web-pages.



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
+---------+------------------------------------------------------------------------------------------------------------------+
