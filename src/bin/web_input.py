"""
This module provides the classes for support web-scraping in Splunk.

The classes included are:

  * SelectorField: a modular input field for verifying that a selector is valid
  * WebsiteInputConfig: a class for getting information from Splunk for configuration of the app
  * DiscoveredURL: represents a URL that was discovered
  * WebInput: the main modular input class
  * WebScraper: a class for performing web-scrapes
"""

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from website_input_app.modular_input import Field, ListField, FieldValidationException, ModularInput, URLField, DurationField, BooleanField, IntegerField, StaticListField
from website_input_app.timer import Timer
from website_input_app.web_client import DefaultWebClient, RequestTimeout, ConnectionFailure, LoginFormNotFound, FormAuthenticationFailed, WebClientException
from website_input_app.web_driver_client import FirefoxClient, ChromeClient
from website_input_app.event_writer import StashNewWriter

from splunk.models.base import SplunkAppObjModel
from splunk.models.field import Field as ModelField
from splunk.models.field import IntField as ModelIntField

import logging
from logging import handlers
import hashlib
import httplib2
import socket
import sys
import os
import splunk
import chardet
from selenium.common.exceptions import WebDriverException
import re
from collections import OrderedDict
from urlparse import urlparse, urljoin, urlunsplit, urlsplit
import lxml.html
from lxml.etree import XMLSyntaxError

from cssselector import CSSSelector
from __builtin__ import classmethod

def setup_logger():
    """
    Setup a logger.

    Note that the modular input base class has a logger too. However, it isn't currently used
    because there are several classmethods that don't have access to the logger.
    """

    logger = logging.getLogger('web_input_modular_input')
    logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(logging.DEBUG)

    file_handler = handlers.RotatingFileHandler(make_splunkhome_path(['var', 'log', 'splunk', 'web_input_modular_input.log']), maxBytes=25000000, backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger

logger = setup_logger()

class SelectorField(Field):
    """
    Represents a selector for getting information from a web-page. The selector is converted to a
    LXML CSS selector instance.
    """

    @classmethod
    def parse_selector(cls, value, name):

        if value is not None and len(value.strip()) != 0:
            try:
                # Use the HTML translation so that selectors match accordingly ("DIV" should match "div")
                return CSSSelector(value, translator='html')
            except AssertionError as e:
                raise FieldValidationException("The value of '%s' for the '%s' parameter is not a valid selector: %s" % (str(value), name, str(e)))

    def to_python(self, value, session_key=None):
        Field.to_python(self, value, session_key)

        return SelectorField.parse_selector(value, self.name)

    def to_string(self, value):
        return value.css

class WebsiteInputConfig(SplunkAppObjModel):

    resource = '/admin/app_website_input'
    proxy_server = ModelField()
    proxy_port = ModelIntField()
    proxy_type = ModelField()
    proxy_user = ModelField()
    proxy_password = ModelField()

class DiscoveredURL(object):

    depth = None
    processed = False

    def __init__(self, depth, processed=False):
        self.depth = depth
        self.processed = False


class WebInput(ModularInput):
    """
    The web input modular input connects to a web-page obtains information from it.
    """

    OUTPUT_USING_STASH = True

    # Static variables for when to output results
    OUTPUT_RESULTS_ALWAYS = 'always'
    OUTPUT_RESULTS_WHEN_MATCHES_CHANGE = 'when_matches_change'
    OUTPUT_RESULTS_WHEN_CONTENTS_CHANGE = 'when_contents_change'

    OUTPUT_RESULTS_OPTIONS = [OUTPUT_RESULTS_ALWAYS, OUTPUT_RESULTS_WHEN_MATCHES_CHANGE, OUTPUT_RESULTS_WHEN_CONTENTS_CHANGE]

    # The following define which secure password entry to use for the proxy
    PROXY_PASSWORD_REALM = 'website_input_app_proxy'
    PROXY_PASSWORD_USERNAME = 'IN_CONF_FILE'

    def __init__(self, timeout=30, **kwargs):

        scheme_args = {'title': "Web-pages",
                       'description': "Retrieve information from web-pages",
                       'use_external_validation': "true",
                       'streaming_mode': "xml",
                       'use_single_instance': "true"}

        args = [
            Field("title", "Title", "A short description (typically just the domain name)", empty_allowed=False),
            URLField("url", "URL", "The URL to connect to (must be be either HTTP or HTTPS protocol)", empty_allowed=False, require_https_on_cloud=True),
            DurationField("interval", "Interval", "The interval defining how often to perform the check; can include time units (e.g. 15m for 15 minutes, 8h for 8 hours)", empty_allowed=False),
            IntegerField("timeout", "Timeout", 'The timeout (in number of seconds)', none_allowed=True, empty_allowed=True),
            SelectorField("selector", "Selector", "A selector that will match the data you want to retrieve", none_allowed=True, empty_allowed=True),

            # HTTP client options
            Field("user_agent", "User Agent", "The user-agent to use when communicating with the server", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("browser", "Browser", 'The browser to use', none_allowed=True, empty_allowed=True),

            # Output options
            ListField("name_attributes", "Field Name Attributes", "A list of attributes to use for assigning a field name", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            BooleanField("use_element_name", "Use Element Name as Field Name", "Use the element's tag name as the field name", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            BooleanField("output_as_mv", "Output as Multi-value Field", "Output the matches as multi-value field", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            StaticListField("output_results", "Indicates when results output should be created", "Output the matches only when results changed", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False, valid_values=WebInput.OUTPUT_RESULTS_OPTIONS),
            BooleanField("raw_content", "Raw content", "Return the raw content returned by the server", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            BooleanField("empty_matches", "Empty matches", "Include empty rows (otherwise, they are excluded)", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("text_separator", "Text Separator", 'A string that will be placed between the extracted values (e.g. a separator of ":" for a match against "<a>tree</a><a>frog</a>" would return "tree:frog")', none_allowed=True, empty_allowed=True),

            # Spidering options
            IntegerField("page_limit", "Discovered page limit", "A limit on the number of pages that will be auto-discovered", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            IntegerField("depth_limit", "Depth limit", "A limit on how many levels deep the search for pages will go", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("url_filter", "URL Filter", "A wild-card that will indicate which pages it should search for matches in", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),

            # Authentication options
            Field("username", "Username", "The username to use for authenticating", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("password", "Password", "The password to use for authenticating", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("username_field", "Username field", "The name of the username field on the login form", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("password_field", "Password field", "The name of the password field on the login form", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            URLField("authentication_url", "Authentication URL", "The URL of the login form", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False, require_https_on_cloud=True)
        ]

        ModularInput.__init__(self, scheme_args, args)

        # Make the base class use our logger
        self.logger = logger

        if timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 30

    @classmethod
    def get_file_path(cls, checkpoint_dir, stanza):
        """
        Get the path to the checkpoint file.

        Arguments:
        checkpoint_dir -- The directory where checkpoints ought to be saved
        stanza -- The stanza of the input being used
        """

        return os.path.join(checkpoint_dir, hashlib.md5(stanza).hexdigest() + ".json")

    def get_proxy_config(self, session_key, stanza="default"):
        """
        Get the proxy configuration

        Arguments:
        session_key -- The session key to use when connecting to the REST API
        stanza -- The stanza to get the proxy information from (defaults to "default")
        """

        # Don't allow the use of a proxy server on Splunk Cloud since this could
        # allow unencrypted communication. Cloud shouldn't need the use of a proxy anyways.
        if self.is_on_cloud(session_key):
            return "http", None, None, None, None

        # If the stanza is empty, then just use the default
        if stanza is None or stanza.strip() == "":
            stanza = "default"

        # Get the proxy configuration
        try:
            website_input_config = WebsiteInputConfig.get(WebsiteInputConfig.build_id( stanza, "website_input", "nobody"), sessionKey=session_key)

            logger.debug("Proxy information loaded, stanza=%s", stanza)

        except splunk.ResourceNotFound:
            logger.error('Unable to find the proxy configuration for the specified configuration stanza=%s, error="not found"', stanza)
            raise
        except splunk.SplunkdConnectionException:
            logger.error('Unable to find the proxy configuration for the specified configuration stanza=%s error="splunkd connection error"', stanza)
            raise

        # Get the proxy password from secure storage (if it exists)
        secure_password = self.get_secure_password(realm=WebInput.PROXY_PASSWORD_REALM,
                                                   username=WebInput.PROXY_PASSWORD_USERNAME,
                                                   session_key=session_key)

        if secure_password is not None:
            proxy_password = secure_password['content']['clear_password']
            self.logger.debug("Loaded the proxy password from secure storage")
        else:
            proxy_password = website_input_config.proxy_password

        return website_input_config.proxy_type, website_input_config.proxy_server, website_input_config.proxy_port, website_input_config.proxy_user, website_input_config.proxy_password

    def hash_data(self, data, ignore_keys=None):
        """
        Hash the data and compute a SHA224 hex digest that uniquely represents the data.

        Arguments:
        data -- The data to hash
        ignore_keys -- A list of keys to ignore in the dictionaries
        """

        # Make a hasher capable of handling SHA224
        hash_data = hashlib.sha224()

        # Update the hash data accordingly
        self.update_hash(data, hash_data, ignore_keys)

        # Compute the hex result
        return hash_data.hexdigest()

    def update_hash(self, data, hash_data, ignore_keys=None):
        """
        Update the hash data.

        Arguments:
        data -- The data to hash
        hash_data -- The existing hash that contains the hash thus far
        ignore_keys -- A list of keys to ignore in the dictionaries
        """

        # Handle the dictionary
        if isinstance(data, dict) or isinstance(data, OrderedDict):

            # Sort the dictionary by key
            for key, value in sorted(data.items()):

                if ignore_keys is None or key not in ignore_keys:
                    self.update_hash(key, hash_data, ignore_keys)
                    self.update_hash(value, hash_data, ignore_keys)

        # If the input is a string
        elif isinstance(data, basestring):
            hash_data.update(data)

        elif isinstance(data, list) and not isinstance(data, basestring):

            # Sort the list
            data.sort()

            for entry in data:
                self.update_hash(entry, hash_data, ignore_keys)

        else:
            hash_data.update(str(data))

    def run(self, stanza, cleaned_params, input_config):

        # Make the parameters
        interval           = cleaned_params["interval"]
        title              = cleaned_params["title"]
        url                = cleaned_params["url"]
        selector           = cleaned_params.get("selector", None)
        username           = cleaned_params.get("username", None)
        password           = cleaned_params.get("password", None)
        name_attributes    = cleaned_params.get("name_attributes", [])
        user_agent         = cleaned_params.get("user_agent", None)
        timeout            = cleaned_params.get("timeout", self.timeout)
        sourcetype         = cleaned_params.get("sourcetype", "web_input")
        host               = cleaned_params.get("host", None)
        index              = cleaned_params.get("index", "default")
        conf_stanza        = cleaned_params.get("configuration", None)
        use_element_name   = cleaned_params.get("use_element_name", False)
        page_limit         = cleaned_params.get("page_limit", 1)
        url_filter         = cleaned_params.get("url_filter", None)
        depth_limit        = cleaned_params.get("depth_limit", 25)
        raw_content        = cleaned_params.get("raw_content", False)
        text_separator     = cleaned_params.get("text_separator", " ")
        browser            = cleaned_params.get("browser", WebScraper.INTEGRATED_CLIENT)
        output_as_mv       = cleaned_params.get("output_as_mv", True)
        output_results     = cleaned_params.get("output_results", None)
        username_field     = cleaned_params.get("username_field", None)
        password_field     = cleaned_params.get("password_field", None)
        authentication_url = cleaned_params.get("authentication_url", None)
        source             = stanza
        
        if self.needs_another_run(input_config.checkpoint_dir, stanza, interval):
            
            # Don't scan the URL if the URL is unencrypted and the host is on Cloud
            if self.is_on_cloud(input_config.session_key) and not url.scheme == "https":
                self.logger.warn("The URL will not be processed because the host is running on Splunk Cloud and the URL isn't using encryption, url=%s", url.geturl())
                return

            # Don't scan the URL if the login URL is unencrypted and the host is on Cloud
            if self.is_on_cloud(input_config.session_key) and authentication_url is not None and authentication_url.scheme != "https":
                self.logger.warn("The URL will not be processed because the host is running on Splunk Cloud and the login URL isn't using encryption, authentication_url=%s", authentication_url.geturl())
                return

            # Get the proxy configuration
            try:
                proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = self.get_proxy_config(input_config.session_key, conf_stanza)
            except splunk.ResourceNotFound:
                logger.error("The proxy configuration could not be loaded (resource not found). The execution will be skipped for now for this input with stanza=%s", stanza)
                return
            except splunk.SplunkdConnectionException:
                logger.error("The proxy configuration could not be loaded (splunkd connection problem). The execution will be skipped for now for this input with stanza=%s", stanza)
                return

            # Get the secure password if necessary
            if username is not None:
                secure_password = self.get_secure_password(realm=stanza, session_key=input_config.session_key)

                if secure_password is not None:
                    password = secure_password['content']['clear_password']
                    self.logger.debug("Successfully loaded the secure password for input=%s", stanza)
            
            # Get the information from the page
            result = None
            
            try:
                
                # Make sure the page_limit is not too small
                if page_limit < 1 or page_limit is None or page_limit == "":
                    logger.warn("The parameter is too small for page_limit=%r", page_limit)
                    page_limit = 1
                    
                # Make sure the depth_limit is valid
                if depth_limit < 1 or depth_limit is None or depth_limit == "":
                    logger.warn("The parameter is too small for depth_limit=%r", depth_limit)
                    depth_limit = 50
                    
                # Determine how to make the match fields
                output_matches_as_mv = True
                output_matches_as_separate_fields = False
                
                if not output_as_mv:
                    output_matches_as_mv = False
                    output_matches_as_separate_fields = True
                
                additional_fields = {
                    'title' : title
                }
                
                # Make an instance of the web-scraper and initialize it
                web_scraper = WebScraper(timeout)

                web_scraper.set_proxy(proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)
                web_scraper.user_agent = user_agent
                web_scraper.set_authentication(username, password, authentication_url, username_field, password_field)

                # Perform the scrape
                result = web_scraper.scrape_page(url, selector, name_attributes,
                                                 use_element_name=use_element_name,
                                                 page_limit=page_limit,
                                                 depth_limit=depth_limit, url_filter=url_filter,
                                                 include_raw_content=raw_content,
                                                 text_separator=text_separator,
                                                 browser=browser,
                                                 output_matches_as_mv=output_matches_as_mv,
                                                 output_matches_as_separate_fields=output_matches_as_separate_fields,
                                                 additional_fields=additional_fields,
                                                 https_only=self.is_on_cloud(input_config.session_key))
                
                matches = 0
                
                if result:
                    matches = len(result)
                else:
                    logger.debug("No match returned in the result")

                logger.info("Successfully executed the website input, matches_count=%r, stanza=%s, url=%s", matches, stanza, url.geturl())

            except LoginFormNotFound as e:
                logger.warn('Form authentication failed since the form could not be found, stanza=%s', stanza)

            except FormAuthenticationFailed as e:
                logger.warn('Form authentication failed, stanza=%s, error="%s"', stanza, str(e))

            except WebClientException as e:
                logger.warn('Client connection failed, stanza=%s, error="%s"', stanza, str(e))

            except Exception:
                logger.exception("An exception occurred when attempting to retrieve information from the web-page, stanza=%s", stanza) 
            
            # Process the result (if we got one)
            if result is not None:
                
                # Keep a list of the matches so that we can determine if any of results changed
                result_hashes = []

                # Determine the prior hash of the results
                checkpoint_data = self.get_checkpoint_data(input_config.checkpoint_dir, stanza)

                if checkpoint_data is None:
                    checkpoint_data = {}

                # Compute the hash of the results
                with Timer() as timer:
                    matches_hash = self.hash_data(result, WebScraper.GENERATED_FIELDS)

                logger.debug("Hash of results calculated, time=%sms, hash=%s, prior_hash=%s", round(timer.msecs, 3), matches_hash, checkpoint_data.get('matches_hash', ''))
                
                # Assign a default for the content hash; it will be populated later
                content_hash = ""

                # Don't output the results if we are set to not output results unless the matches change
                if output_results == WebInput.OUTPUT_RESULTS_WHEN_MATCHES_CHANGE and checkpoint_data.get('matches_hash', '') == matches_hash:
                    logger.info("Matches data matched the prior result, it will be skipped since output_results=%s, hash=%s", output_results, matches_hash)

                else:
                    
                    # Build up a list of the hashes so that we can determine if the content changed
                    for r in result:

                        # Add the hash
                        if r.get('content_sha224', None) != None:
                            result_hashes.append(r.get('content_sha224', ''))


                    # Compute a hash on the results
                    content_hash = self.hash_data(result_hashes)

                    # Check to see if the content changed
                    # Don't output the results if we are set to not output results unless the matches change
                    if output_results == WebInput.OUTPUT_RESULTS_WHEN_CONTENTS_CHANGE and checkpoint_data.get('content_hash', '') == content_hash:
                        logger.info("Content data matched the prior result, it will be skipped since output_results=%s, hash=%s", output_results, content_hash)

                    else:

                        # Process each event
                        for r in result:

                            # Send the event
                            if self.OUTPUT_USING_STASH:

                                # Write the event as a stash new file
                                writer = StashNewWriter(index=index, source_name=source, file_extension=".stash_web_input", sourcetype=sourcetype, host=host)
                                logger.debug("Wrote stash file=%s", writer.write_event(r))

                            else:

                                # Write the event using the built-in modular input method
                                self.output_event(r, stanza, index=index, source=source, sourcetype=sourcetype, host=host, unbroken=True, close=True, encapsulate_value_in_double_quotes=True)

                # Get the time that the input last ran
                last_ran = self.last_ran(input_config.checkpoint_dir, stanza)

                # Make the new checkpoint data dictionary
                new_checkpoint_data = {
                    'last_run' : self.get_non_deviated_last_run(last_ran, interval, stanza),
                    'matches_hash' : matches_hash,
                    'content_hash' : content_hash
                }

                # Save the checkpoint so that we remember when we last executed this
                self.save_checkpoint_data(input_config.checkpoint_dir, stanza, new_checkpoint_data)

class WebScraper(object):
    """
    This class performs the operation of web-scraping.
    """

    RESERVED_FIELD_NAMES = [
        # Splunk reserved fields:
        'source',
        'sourcetype',
        'host',
        '_time',
        'punct',

        # Internal reserved fields:
        'request_time',
        'response_code',
        'raw_match_count'
    ]

    FIREFOX = "firefox"
    INTEGRATED_CLIENT = "integrated_client"
    SAFARI = "safari"
    INTERNET_EXPLORER = "internet_explorer"
    CHROME = "chrome"

    SUPPORTED_BROWSERS = [INTEGRATED_CLIENT, FIREFOX, CHROME]

    GENERATED_FIELDS = ['browser', 'response_size', 'response_code', 'request_time', 'url',
                        'content_md5', 'content_sha224', 'encoding', 'raw_match_count', 'content',
                        'timed_out', 'title', '_time']

    # Below are the class parameters

    # Character set detection settings
    charset_detect_meta_enabled = True
    charset_detect_content_type_header_enabled = True
    charset_detect_sniff_enabled = True

    # Proxy settings
    proxy_type = "http"
    proxy_server = None
    proxy_port = None
    proxy_user = None
    proxy_password = None

    # Authentication settings
    username = None
    password = None
    username_field = None
    password_field = None
    authentication_url = None

    # Miscellaneous settings
    timeout = 30
    user_agent = None

    def __init__(self, timeout=30):
        self.timeout = timeout

    def set_proxy(self, proxy_type, proxy_server, proxy_port, proxy_user, proxy_password):
        """
        Set the proxy server to use.

        Arguments:
        proxy_type -- The type of the proxy server
        proxy_server -- The server
        proxy_port -- The port of the proxy server (an integer)
        proxy_user -- The username
        proxy_password -- The password
        """

        self.proxy_type = proxy_type
        self.proxy_server = proxy_server
        self.proxy_port = proxy_port
        self.proxy_user = proxy_user
        self.proxy_password = proxy_password

    def set_authentication(self, username, password, authentication_url=None, username_field=None, password_field=None, autodiscover_fields=True):
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.authentication_url = authentication_url

    def set_charset_detection(self, charset_detect_meta_enabled,
            charset_detect_content_type_header_enabled,
            charset_detect_sniff_enabled):
        """
        Set the strategy to use for detecting the contenttype

        Arguments:
        charset_detect_meta_enabled -- The type of the proxy server
        charset_detect_content_type_header_enabled -- The server
        charset_detect_sniff_enabled -- The port of the proxy server (an integer)
        """

        self.charset_detect_meta_enabled = charset_detect_meta_enabled
        self.charset_detect_content_type_header_enabled = charset_detect_content_type_header_enabled
        self.charset_detect_sniff_enabled = charset_detect_sniff_enabled

    @classmethod
    def append_if_not_empty(cls, str1, str2, separator, include_empty=False):
        """
        Append the strings together if they are not blank.

        Arguments:
        str1 -- The first string
        str2 -- The second string
        separator -- The separator to put between the strings if they aren't blank
        """

        if str1 is None:
            str1 = ""

        if str2 is None:
            str2 = ""

        if separator is None:
            separator = " "

        if include_empty or (len(str1) > 0 and len(str2) > 0):
            return str1 + separator + str2
        if len(str1) > 0:
            return str1
        if len(str2) > 0:
            return str2
        else:
            return ""

    @classmethod
    def get_text(cls, element, text_separator=" ", include_empty=False):
        """
        Get the accumulated text from the child nodes.

        Arguments:
        element -- The element to get the text from
        text_separator -- The content to put between each text node that matches within a given selector
        """

        # Assign a default value to the separator
        if text_separator is None:
            text_separator = " "

        if element.text is not None:
            text = element.text.strip()
        else:
            text = None

        # Iterate through the child nodes and add up the text
        for child_element in element:

            text = cls.append_if_not_empty(text, WebScraper.get_text(child_element, text_separator), text_separator, include_empty)

            # Get the tail text
            if child_element.tail:
                tail_text = child_element.tail.strip()
                text = cls.append_if_not_empty(text, tail_text, text_separator, include_empty)

        if text is not None:
            return text.strip()
        else:
            return ""

    @classmethod
    def escape_field_name(cls, name):
        name = re.sub(r'[^A-Z0-9]', '_', name.strip(), flags=re.IGNORECASE)

        if len(name) == 0:
            return "blank"

        if name in cls.RESERVED_FIELD_NAMES:
            return "match_" + name

        return name

    @classmethod
    def detect_encoding(cls, content, response, charset_detect_meta_enabled=True, charset_detect_content_type_header_enabled=True, charset_detect_sniff_enabled=True):
        """
        Detect the encoding that is used in the given website/webpage.

        Arguments:
        content -- The downloaded content (as raw bytes) http.request()
        response -- The response object from http.request()
        charset_detect_meta_enabled -- Enable detection from the META attribute in the head tag
        charset_detect_content_type_header_enabled -- Enable detection from the content-type header
        charset_detect_sniff_enabled -- Enable detection by reviewing some of the content and trying different encodings
        """

        # This will contain the detected encoding
        encoding = None

        # Try getting the encoding from the "meta" attribute
        if charset_detect_meta_enabled:
            #http://stackoverflow.com/questions/3458217/how-to-use-regular-expression-to-match-the-charset-string-in-html
            find_meta_charset = re.compile("<meta(?!\s*(?:name|value)\s*=)[^>]*?charset\s*=[\s\"']*([^\s\"'/>]*)", re.IGNORECASE)
            matched_encoding = find_meta_charset.search(content)

            if matched_encoding:
                encoding = matched_encoding.groups()[0]

        # Try getting the encoding from the content-type header
        if encoding is None and charset_detect_content_type_header_enabled:

            if response is not None and 'content-type' in response:
                find_header_charset = re.compile("charset=(.*)", re.IGNORECASE)
                matched_encoding = find_header_charset.search(response['content-type'])

                if matched_encoding:
                    encoding = matched_encoding.groups()[0]

        # Try sniffing the encoding
        if encoding is None and charset_detect_sniff_enabled and not isinstance(content, unicode):
            encoding_detection = chardet.detect(content)
            encoding = encoding_detection['encoding']

        # If all else fails, default to "Windows-1252"
        if encoding is None:
            encoding = "cp1252"

        return encoding

    @classmethod
    def is_url_in_domain(cls, url, domain):
        """
        Determine if the URL is within the given domain.

        Arguments:
        url -- A URL as a string.
        domain -- A string representing a domain (like "textcritical.net")
        """

        if domain is None:
            return True

        # Parse the link
        url_parsed = urlparse(url)

        # Verify the link is within the domain
        return url_parsed.netloc == domain

    @classmethod
    def wildcard_to_re(cls, wildcard):
        """
        Convert the given wildcard to a regular expression.

        Arguments:
        wildcard -- A string representing a wild-card (like "http://textcritical.net*")
        """

        regex = re.escape(wildcard)
        return regex.replace('\*', ".*")

    @classmethod
    def is_url_in_url_filter(cls, url, url_filter):
        """
        Determine if the URL is within the provided filter wild-card.

        Arguments:
        url -- A URL as a string.
        url_filter -- A string representing a wild-card (like "http://textcritical.net*")
        """

        if url_filter is None:
            return True

        # Convert the filter to a regular expression
        url_filter_re = cls.wildcard_to_re(url_filter)

        # See if the filter matches
        if re.match(url_filter_re, url):
            return True
        else:
            return False

    @classmethod
    def remove_anchor(cls, url):
        """
        Removing the anchor from a link.

        Arguments:
        url -- A URL or partial URL
        """

        m = re.search('([^#]*).*', url)
        return m.group(1)

    @classmethod
    def cleanup_link(cls, url, source_url):
        """
        Prepare a link for processing by removing the anchor and making it absolute.

        Arguments:
        url -- A URL or partial URL
        source_url -- The URL from which the URL was obtained from
        """

        if source_url is not None:
            return cls.remove_anchor(urljoin(source_url, url))
        else:
            return cls.remove_anchor(url)

    @classmethod
    def extract_links(cls, lxml_html_tree, source_url, links=None, url_filter=None, https_only=False):
        """
        Get the results from performing a HTTP request and parsing the output.

        Arguments:
        lxml_html_tree -- A parsed XML tree.
        source_url -- The url from which the content came from; this should be a string.
        links -- An array to put the links into
        url_filter -- The URL to filter extraction to (a wild-card as a string)
        https_only -- Only extract links that use HTTPS
        """

        # Set a default for the links argument
        if links is None:
            links = []

        # Get a selector grab the hrefs
        selector = SelectorField.parse_selector("a[href]", "selector")

        # Get the matches
        matches = selector(lxml_html_tree)

        for match in matches:
            attributes = dict(match.attrib)

            # If the a tag has an href, then get it
            if 'href' in attributes:

                # CLeanup the link to remove the local parts like the #
                link = cls.cleanup_link(attributes['href'], source_url)

                # Make sure the link wasn't already in the list
                if https_only and not link.startswith("https://"):
                    # Ignore this link since it isn't using HTTPS
                    pass 
                elif link not in links and cls.is_url_in_url_filter(link, url_filter):
                    links.append(link)

        return links

    def get_result_single(self, web_client, url, selector, name_attributes=[], output_matches_as_mv=True, output_matches_as_separate_fields=False, include_empty_matches=False, use_element_name=False, extracted_links=None, url_filter=None, source_url_depth=0, include_raw_content=False, text_separator=None, browser=None, additional_fields=None, match_prefix=None, empty_value=None, https_only=False):
        """
        Get the results from performing a HTTP request and parsing the output.

        Arguments:
        web_client -- An instance of a WebClient
        url -- The url to connect to. This object ought to be an instance derived from using urlparse
        selector -- A CSS selector that matches the data to retrieve
        name_attributes -- Attributes to use the values for assigning the names
        output_matches_as_mv -- Output all of the matches with the same name ("match")
        output_matches_as_separate_fields -- Output all of the matches as separate fields ("match1", "match2", etc.)
        include_empty_matches -- Output matches that result in empty strings
        use_element_name -- Use the element as the field name
        extracted_links -- The array to place the extract links (will only be done if not None)
        url_filter -- The wild-card to filter extracted URLs to
        source_url_depth -- The depth level of the URL from which this URL was discovered from. This is used for tracking how depth the crawler should go.
        include_raw_content -- Include the raw content (if true, the 'content' field will include the raw content)
        text_separator -- The content to put between each text node that matches within a given selector
        browser -- The browser to use
        additional_fields -- Additional fields to put into the result set
        match_prefix -- A prefix to attach to prepend to the front of the match fields
        empty_value -- The value to use for empty matches
        https_only -- Only extract links that use HTTPS
        """

        try:

            if match_prefix is None:
                match_prefix = ''

            # This will be where the result information will be stored
            result = OrderedDict()

            if additional_fields is not None:
                for k, v in additional_fields.items():
                    result[k] = v

            # Perform the request
            content = web_client.get_url(url.geturl())

            # Detect the encoding
            encoding = self.detect_encoding(content, web_client.get_response_headers())

            result['browser'] = browser

            # Get the size of the content
            result['response_size'] = len(content)

            # Retrieve the meta-data
            if web_client.response_code is not None:
                result['response_code'] = web_client.response_code

            result['url'] = url.geturl()
            result['request_time'] = web_client.response_time

            # Get the hash of the content
            if content is not None:
                result['content_md5'] = hashlib.md5(content).hexdigest()
                result['content_sha224'] = hashlib.sha224(content).hexdigest()

            # Decode the content
            if encoding is not None and encoding != "":
                content_decoded = content.decode(encoding=encoding, errors='replace')

                # Store the encoding in the result
                result['encoding'] = encoding
            else:
                content_decoded = content

            # Parse the HTML
            try:
                tree = lxml.html.fromstring(content_decoded)
            except (ValueError, XMLSyntaxError):
                # lxml will refuse to parse a Unicode string containing XML that declares the encoding even if the encoding declaration matches the encoding used.
                # This is odd since this exception will be thrown even though the app successfully determined the encoding (it matches the declaration in the XML).
                # The app handles this by attempting to parse the content a second time if it failed when using Unicode. This is necessary because I cannot allow
                # lxml to discover the encoding on its own since it doesn't know what the HTTP headers are and cannot sniff the encoding as well as the input does
                # (which uses several methods to determine the encoding).
                logger.info('The content is going to be parsed without decoding because the parser refused to parse it with the detected encoding (http://goo.gl/4GRjJF), url="%s", encoding="%s"', url.geturl(), encoding)

                try:
                    tree = lxml.html.fromstring(content)
                except Exception:
                    logger.info('The content could not be parsed, it doesn\'t appear to be valid HTML, url="%s"', url.geturl())
                    tree = None

            except Exception:
                logger.info('A unexpected exception was generated while attempting to parse the content, url="%s"', url.geturl())

            # Perform extraction if a selector is provided
            if selector is not None and tree is not None:

                # Apply the selector to the DOM tree
                matches = selector(tree)

                # Store the raw match count (the nodes that the CSS matches)
                result['raw_match_count'] = len(matches)
  
                # Get the text from matching nodes
                if output_matches_as_mv:
                    result[match_prefix + 'match'] = []

                # We are going to count how many fields we made
                fields_included = 0

                for match in matches:

                    # Unescape the text in case it includes HTML entities
                    match_text = self.unescape(WebScraper.get_text(match, text_separator, include_empty_matches))

                    # Don't include the field if it is empty
                    if include_empty_matches or len(match_text) > 0:

                        # Use the empty value if necessary     
                        if empty_value is not None and len(empty_value) > 0 and (match_text is None or len(match_text) == 0):
                            match_text = empty_value

                        # Keep a count of how many fields we matched
                        fields_included = fields_included + 1

                        # Save the match
                        field_made = False

                        # Try to use the name attributes for determining the field name
                        for a in name_attributes:

                            attributes = dict(match.attrib)

                            if a in attributes:

                                field_made = True
                                field_name = self.escape_field_name(attributes[a])

                                # If the field does not exist, create it
                                if not field_name in result and output_matches_as_mv:
                                    result[match_prefix + field_name] = [match_text]

                                # If the field exists and we are adding them as mv, then add it
                                elif field_name in result and output_matches_as_mv:
                                    result[match_prefix + field_name].append(match_text)
  
                                # Otherwise, output it as a separate field
                                if output_matches_as_separate_fields:
                                    result[match_prefix + 'match_' + field_name + "_" + str(fields_included)] = match_text

                        # Try to use the name of the element
                        if use_element_name and not field_made:

                            # If the field does not exists, create it
                            if not (match_prefix + match.tag) in result and output_matches_as_mv:
                                result[match_prefix + match.tag] = [match_text]

                            # If the field exists and we are adding them as mv, then add it
                            elif output_matches_as_mv:
                                result[match_prefix + match.tag].append(match_text)

                            # Otherwise, output it as a separate field
                            if output_matches_as_separate_fields:
                                result[match_prefix + 'match_' + match.tag] = match_text

                        # Otherwise, output the fields as generic fields
                        if not field_made:

                            if output_matches_as_mv:
                                result[match_prefix + 'match'].append(match_text) # Note: the 'match' in the dictionary will already be populated

                            if output_matches_as_separate_fields:
                                result[match_prefix + 'match_' + str(fields_included)] = match_text
 
            # Include the raw content if requested
            if include_raw_content:
                result['content'] = content

            # If we are to extract links, do it
            if tree is not None:
                if extracted_links is not None and source_url_depth is not None:

                    for extracted in self.extract_links(tree, url.geturl(), url_filter=url_filter, https_only=https_only):

                        # Add the extracted link if it is not already in the list
                        if extracted not in extracted_links:

                            # Add the discovered URL (with the appropriate depth)
                            extracted_links[extracted] = DiscoveredURL(source_url_depth + 1)
                else:
                    logger.debug("Not extracting links since extracted_links is None")

        # Handle time outs    
        except RequestTimeout:

            # Note that the connection timed out    
            result['timed_out'] = True

        except ConnectionFailure:
            result['timed_out'] = True

        except httplib2.SSLHandshakeError as e:
            logger.warn('Unable to connect to website due to an issue with the SSL handshake, url="%s", message="%s"', url.geturl(), str(e))
            return None # Unable to connect to this site due to an SSL issue

        except httplib2.RelativeURIError:
            return None # Not a real URI

        except Exception:
            logger.exception("A general exception was thrown when executing a web request")
            raise

        return result

    def scrape_page(self, url, selector, name_attributes=[], output_matches_as_mv=True,
                    output_matches_as_separate_fields=False, include_empty_matches=False,
                    use_element_name=False, page_limit=1, depth_limit=50, url_filter=None,
                    include_raw_content=False, text_separator=None, browser=None,
                    additional_fields=None, match_prefix=None, empty_value='NULL',
                    https_only=False):
        """
        Retrieve data from a website.
        
        Arguments:
        url -- The url to connect to. This object ought to be an instance derived from using urlparse
        selector -- A CSS selector that matches the data to retrieve
        name_attributes -- Attributes to use the values for assigning the names
        output_matches_as_mv -- Output all of the matches with the same name ("match")
        output_matches_as_separate_fields -- Output all of the matches as separate fields ("match1", "match2", etc.)
        include_empty_matches -- Output matches that result in empty strings
        use_element_name -- Use the element as the field name
        page_limit -- The page of pages to limit matches to
        depth_limit == The limit on the depth of URLs found
        url_filter -- A wild-card to limit the extracted URLs to
        include_raw_content -- Include the raw content (if true, the 'content' field will include the raw content)
        text_separator -- The content to put between each text node that matches within a given selector
        browser -- The browser to use
        additional_fields -- Additional fields to put into the result set
        match_prefix -- A prefix to attach to prepend to the front of the match fields
        empty_value -- The value to use for empty matches
        https_only -- Only extract links that use HTTPS
        """

        if isinstance(url, basestring):
            url = URLField.parse_url(url, "url")

        if isinstance(selector, basestring):
            selector = SelectorField.parse_selector(selector, "selector")

        logger.info('Running web input, url="%s"', url.geturl())

        results = []

        try:

            # Make the browser client if necessary
            if browser == WebScraper.FIREFOX:
                client = FirefoxClient(timeout=self.timeout, user_agent=self.user_agent, logger=logger)
            elif browser == WebScraper.CHROME:
                client = ChromeClient(timeout=self.timeout, user_agent=self.user_agent, logger=logger)
            else:
                client = DefaultWebClient(self.timeout, user_agent=self.user_agent, logger=logger)

            # Setup the proxy
            client.setProxy(self.proxy_type, self.proxy_server, self.proxy_port, self.proxy_user, self.proxy_password)

            # Setup credentials
            client.setCredentials(self.username, self.password)

            # Do form authentication
            if self.username is not None and self.password is not None and self.authentication_url is not None:
                client.doFormLogin(self.authentication_url.geturl(), self.username_field, self.password_field)

            # Run the scraper and get the results
            extracted_links = OrderedDict()
            extracted_links[url.geturl()] = DiscoveredURL(0)

            # Process each result
            while len(results) < page_limit:

                source_url_depth = 0
                url = None
                
                for k, v in extracted_links.items():
                    
                    if v.processed == False:
                        url = k
                        source_url_depth = v.depth
                        
                        # Track that the URL was checked since we are going to process it
                        extracted_links[k].processed = True
                        
                        # Since we found one, stop looking for one to process
                        break
                
                # Stop if we have no more URLs to process
                if url is None:
                    logger.debug("No more URLs in the list to process")
                    break
                
                # Make the keyword argument list
                kw = {
                        'url_filter' : url_filter,
                        'source_url_depth': source_url_depth,
                        'include_raw_content': include_raw_content,
                        'text_separator': text_separator,
                        'browser': browser,
                        'extracted_links': extracted_links,
                        'match_prefix': match_prefix,
                        'empty_value': empty_value
                      }
                
                # Don't have the function extract URLs if the depth limit has been reached
                if source_url_depth >= depth_limit:
                    kw['extracted_links'] = None

                # Perform the scrape
                result = self.get_result_single(client, urlparse(url), selector,
                                                name_attributes, output_matches_as_mv,
                                                output_matches_as_separate_fields,
                                                include_empty_matches, use_element_name,
                                                additional_fields=additional_fields, **kw)
                
                # Append the result
                if result is not None:
                    results.append(result)
                
        except (LoginFormNotFound, FormAuthenticationFailed, WebClientException) as e:
            raise e

        except Exception:
            # TODO: remove this one or the one in get_result_single()
            logger.exception("A general exception was thrown when executing a web request")
            raise

        finally:
            if client:
                client.close()
        
        return results
    
    @classmethod
    def unescape(cls, text):
        """
        Removes HTML or XML character references and entities from a text string. Return the plain text, as a Unicode string, if necessary.
        
        Argument:
        text -- The HTML (or XML) source text.
        """

        if text is None:
            return None

        import HTMLParser
        h = HTMLParser.HTMLParser()
        
        return h.unescape(text)
            
if __name__ == '__main__':
    try:
        web_input = WebInput()
        web_input.execute()
        sys.exit(0)
    except Exception:
        logger.exception("Unhandled exception was caught, this may be due to a defect in the script") # This logs general exceptions that would have been unhandled otherwise (such as coding errors)
        raise
