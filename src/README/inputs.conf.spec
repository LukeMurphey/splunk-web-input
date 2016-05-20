[web_input://default]
* Configure an input for retrieving information from a website

url = <value>
* The URL to obtain the data from

interval = <value>
* Indicates how often to extract the data from the page

title = <value>
* A title of the input

selector = <value>
* A CSS selector that matches the data you want to retrieve

username = <value>
* Defines the username to use for authenticating (only HTTP authentication supported)

password = <value>
* Defines the password to use for authenticating (only HTTP authentication supported)

name_attributes = <value>
* Defines the attributes that ought to be used for finding the information for naming a the matching field

user_agent = <value>
* Defines the user-agent string used by the HTTP client

use_element_name = <value>
* Indicates if the element name ought to be used as the source for the field name (useful for XML files)

page_limit = <value>
* Indicates the maximum number of pages to discover from URL extraction

url_filter = <value>
* Indicates what URLs the spider should be limited to

depth_limit = <value>
* Indicates how many pages deep to look for matches

raw_content = <value>
* Indicates if the raw content should be included too

text_separator = <value>
* Defines the string that will be placed between the extracted values (e.g. a separator of ":" for a match against "<a>tree</a><a>frog</a>" would return "tree:frog")