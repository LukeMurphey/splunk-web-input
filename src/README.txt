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

Install this app into Splunk by doing the following:

  1. Log in to Splunk Web and navigate to "Apps » Manage Apps" via the app dropdown at the top left of Splunk's user interface
  2. Click the "install app from file" button
  3. Upload the file by clicking "Choose file" and selecting the app
  4. Click upload
  5. Restart Splunk if a dialog asks you to

Once the app is installed, you can use the app by configuring a new input:
  1. Open the "Website Input" app from the main launcher.
  2. Open the "Inputs" view from the app navigation
  3. Click "Create a New Input" to open the wizard to create a new input

Alternatively, you can configure the app from the Splunk manager:
  1. Navigate to "Settings » Data Inputs" at the menu at the top of Splunk's user interface.
  2. Click "Web-pages"
  3. Click "New" to make a new instance of an input



================================================
Getting Support
================================================

Go to the following website if you need support:

     http://splunk-base.splunk.com/apps/1818/answers/

You can access the source-code and get technical details about the app at:

     https://github.com/LukeMurphey/splunk-web-input



================================================
Third Party Dependencies
================================================

See the following for a list of the third-party dependencies included in this app: https://lukemurphey.net/projects/splunk-web-input/wiki/Dependencies/11



================================================
FAQ
================================================

Q: How do I enable the use of a proxy server?

A: To use a proxy server, re-run the app setup page and enter the information for a proxy server.

----------------------------------------------------------------------------------------------

Q: Can I allow non-admin users to make and edit inputs?

A: Yes, just assign users the "edit_modinput_web_input" capability. You will likely want to give them the "list_inputs" capability too.



================================================
Known Issues
================================================

* Chrome does not recognize username and password authentication for proxy configurations. You will need to setup the browser directly with a custom proxy setting before running the input.


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
| 1.1     | Added ability to specify the user-agent string                                                                   |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.1.1   | Updated to the latest version of the modular input library; should fix problems where the input crashes          |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.1.2   | Fixed issue where fields without spaces were not being extracted as multi-value fields by default                |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.1.3   | Fixed issue where you had to re-type the password every-time you wanted to edit an input                         |
|---------|------------------------------------------------------------------------------------------------------------------|
| 1.2.0   | Fixed issue where the selector would sometimes not match if the content was upper-case and the selector wasn't   |
|         | Added a BNF file for the search command                                                                          |
|         | Added the ability to use the tag names as the field names                                                        |
|---------|------------------------------------------------------------------------------------------------------------------|
| 2.0     | Added ability to crawl websites for matches                                                                      |
|---------|------------------------------------------------------------------------------------------------------------------|
| 2.1     | Simplified the data input configuration screen                                                                   |
|         | Added ability to include the raw content                                                                         |
|         | Added ability to specify a custom string that will separate extracted values                                     |
|         | Fixed incorrect reporting of matches count                                                                       |
|---------|------------------------------------------------------------------------------------------------------------------|
| 3.0     | Added rendering using a browser (to get page contents after JS rendering has executed)                           |
|         | MD5 and SHA224 hashes are now included in the results                                                            |
|         | Added ability to output matches as separate fields                                                               |
|         | Matches are now listed in results in order that they discovered                                                  |
|         | The crawler now discovers URLs in pages that didn't match the selector                                           |
|         | SSL handshake errors no longer terminate a page scraping session                                                 |
|         | Added extra logging for errors when attempting to load proxy configuration                                       |
|---------|------------------------------------------------------------------------------------------------------------------|
| 3.1     | Added ability to grant access to make inputs to non-admin users                                                  |
|---------|------------------------------------------------------------------------------------------------------------------|
| 3.1.1   | Fixed problem where you could not create new inputs                                                              |
|---------|------------------------------------------------------------------------------------------------------------------|
| 3.1.2   | Fixed problem where matches were not visible when the content is very long                                       |
|---------|------------------------------------------------------------------------------------------------------------------|
| 3.2     | Added ability to view results in search from the modular input creation page                                     |
|         | Improved search BNF                                                                                              |
|---------|------------------------------------------------------------------------------------------------------------------|
| 3.2.1   | Improved compatibility with Splunk versions                                                                      |
|         | Fixed overly restrictive URL validation                                                                          |
|         | Fixed issue where some parts of the stash file may not have been indexed, losing parts of large result sets      |
|         | Fixed controller logs which were not sourcetyped correctly                                                       |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.0     | Added UI for managing inputs and viewing the results                                                             |
|         | Added support for rendering data with newer versions of Firefox                                                  |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.0.1   | Fixed issue where loading pages without styles reloaded the main URL                                             |
|         | Added permission checking to the editor                                                                          |
|         | Fixed issue where the field preview would sometimes show empty fields when none existed                          |
|         | Fixed issue where disabling output_mv output caused the preview to show no results                               |
|         | Improved error message for invalid selectors                                                                     |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.0.2   | Fixed issue where HTTP authentication didn't work with Firefox                                                   |
|         | Fixed issue where Firefox rendering didn't work on headless environments                                         |
|         | Improved icons                                                                                                   |
|         | Improved the sparkline on the overview dashboard to make it easier to read                                       |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.1     | Fixed issue where some sites could not be previewed                                                              |
|         | Fixed issue where selectors would not match an ID that was not lowercase                                         |
|         | Added ability to include empty matches                                                                           |
|         | Added ability to delete inputs                                                                                   |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.1.1   | Fixed issue where Firefox driver was not correctly added to the path on Windows                                  |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.1.2   | Added support for Splunk installs running with the free license                                                  |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.1.3   | Fixed issue where the host field was not being set properly                                                      |
|         | Reduced some unimportant log messages to debug level                                                             |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.2     | Added the ability to output results only when the results change or when the contents of the pages change        |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.2.1   | Improved compatibility with Splunk 6.6                                                                           |
|         | Fixed issue where you cannot enable inputs sometimes                                                             |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.3     | The app restricts input creation to sites that use encryption for Cloud customers                                |
|         | Passwords are now stored using Splunk secure storage                                                             |
|         | Setup page has been updated to make it easier to use                                                             |
|         | Pages can now be rendered using Google Chrome                                                                    |
|         | Added help page to guide users on how to use a web browser for rendering; added browser test to input page       |
|         | Fixed a couple small bugs on the Overview dashboard                                                              |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.4     | Added support for forms authentication                                                                           |
|         | Added ability to set a default value for the user-agent globally                                                 |
|         | Removed support for proxy authentication on Splunk Cloud                                                         |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5     | Added support for forms authentication with browsers                                                             |
|         | Fixed issue where user-agent string was not set for Firefox and Chrome                                           |
|         | Fixed issue where the browser testing functionality on the UI didn't use the proxy server                        |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5.1   | Input is now resilient to transient Splunkd outages                                                              |
|         | Fixed issue where index selection input was super-wide on Splunk 7.0                                             |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5.2   | Input now handles large files much better by only downloading the first 512 KB of the file                       |
|         | Updated the Chrome driver so that the input works with newer versions of Chrome                                  |
|         | The input creation wizard auto-suggests a URL filter now when using spidering                                    |
|         | Output is not streamed (as opposed to being cached) in order to reduce memory usage                              |
|         | The input now gracefully handles websites that return a bad encoding                                             |
|         | Fixed issue where you could not drill-down on logs from the health dashboard                                     |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5.3   | Updating the styling to work better on Splunk 7.1                                                                |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5.4   | Fixed the "when_matches_change" setting of "output_results" made results even the matches hadn't changed         |
|         | Fixed issue where the severity chart filtered based on the severity filter                                       |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5.5   | Improved styling on Splunk 7.0+                                                                                  |
|         | Fixed issue where passwords were not loaded if there were more than 30                                           |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5.6   | Fixed error that occurred when output values as multi-valued fields                                              |
|         | Fixed issue where proxy password from secure storage was not being used                                          |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5.7   | Fixed another error that occurred when output values as multi-valued fields                                      |
|         | Updated the geckodriver to 0.24 so that newer versions of Firefox work                                           |
|         | Added link to search logs to determine why browser test failed                                                   |
|         | Fixed issue where integrated browser test failed on the input wizard                                             |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5.8   | Updated to the modular input base class 2.1.8                                                                    |
|         | Converted the controller to a REST handler                                                                       |
|         | Python 2 + 3 support                                                                                             |
|         | Added more logs to the health view                                                                               |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5.9   | Added link to open URL in new tab                                                                                |
|         | Improved code for communicating to the preview iframe                                                            |
|---------|------------------------------------------------------------------------------------------------------------------|
| 4.5.10  | Results now retain the original ordering                                                                         |
+---------+------------------------------------------------------------------------------------------------------------------+
