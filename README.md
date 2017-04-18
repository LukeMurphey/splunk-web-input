# Splunk Website Input App

## A Splunk app for obtaining information from web apps

This app allows you to download contents of web-pages and index them. You can get the app here on [Splunkbase](https://splunkbase.splunk.com/app/1818).

![screenshot of results](https://github.com/LukeMurphey/splunk-web-input/blob/master/related/screenshot_main_1.png "Results")


### Features

Website Data Extraction: setup an input that will extract data from a web-page and get it into Splunk
Data Preview: click "Preview results" on the input configuration page to get a sample of the what the output would look like before you save the configuration
Configuration

### Initial setup

Once you install the app, it will ask you to set it up on the app configuration page. The setup only contains options related to configuring a proxy server. If no proxy server is used, you can just press save.

### Creating an input

#### CSS selectors

You will need to create an input to define the websites that you would like to extract information from. You can setup a new input using Splunk's manager at Settings » Data Inputs » Web-pages. The most difficult part of configuring the app is making the CSS selector that will capture the data you want. See [W3schools](http://www.w3schools.com/cssref/css_selectors.asp) for information on how to create CSS selectors.

** Tip, CSS selector extraction in chrome;**

* Navigate to the webpage to be splunked
* Right click on the page > select “Inspect element”. 
* You will then have a new section on the right of the web page, containing the elements of the page
* Move your mouse down this text until the specific part of the page you are interested in highlights.
* Right click
* Select “Copy CSS Path“ 
* Go back to the Splunk app setup page and paste this into the “Selector” field” (Example: #TIRatesDisplay_tblTermDeposit)
* Repeat this for other elements on the same page you wish to ingest separated by commas (Example: #TIRatesDisplay_tblTermDeposit, #TIRatesDisplay_tblLoan)

You can also use the new wizard form to make creating the selector easier:

![screenshot of wizard_form](https://github.com/LukeMurphey/splunk-web-input/blob/master/related/screenshot_selector_3.png "Wizard for extracting results")

#### Outputs
You can usually ignore the "Output" section. This is only necessary if you want to name the fields that the input will get based on content within the page [(see "Can I use attributes to set the field names?" for details).](http://lukemurphey.net/projects/splunk-web-input/wiki/FAQ#Can-I-use-attributes-to-set-the-field-names)

#### Authentication
The "Authentication" can be left blank unless the web-page requires authentication. Only HTTP authentication is supported at the current time.

### FAQs

See the links below for answers to frequently asked questions:

[Can I specify more than one selector (to match different things on a single page)?](http://lukemurphey.net/projects/splunk-web-input/wiki/FAQ)

[Can I use attributes to set the field names?](http://lukemurphey.net/projects/splunk-web-input/wiki/FAQ)

### More Information

This project is open source. 

See [GitHub](https://github.com/LukeMurphey/splunk-web-input) for the source or [LukeMurphey.net](http://lukemurphey.net/projects/splunk-web-input/wiki) for more information.

The pacakge is available on [Splunkbase](https://splunkbase.splunk.com/app/1818)
