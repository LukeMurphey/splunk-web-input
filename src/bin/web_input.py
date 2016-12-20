
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path, get_apps_dir
from website_input_app.modular_input import Field, ListField, FieldValidationException, ModularInput, URLField, DurationField, BooleanField, IntegerField
from splunk.models.base import SplunkAppObjModel
from splunk.models.field import Field as ModelField
from splunk.models.field import IntField as ModelIntField 

import logging
from logging import handlers
import hashlib
import socket
import sys
import time
import os
import splunk
import chardet
import platform
from selenium import webdriver
import re
from collections import OrderedDict
from urlparse import urlparse, urljoin, urlunsplit, urlsplit
from website_input_app.event_writer import StashNewWriter
import httplib2
from httplib2 import socks
import lxml.html
from lxml.etree import XMLSyntaxError

from cssselector import CSSSelector
from __builtin__ import classmethod

from pyvirtualdisplay import Display
from easyprocess import EasyProcessCheckInstalledError

def setup_logger():
    """
    Setup a logger.
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
    Represents a selector for getting information from a web-page. The selector is converted to a LXML CSS selector instance.
    """
    
    @classmethod
    def parse_selector(cls, value, name):
        
        if value is not None and len(value.strip()) != 0:
            try:
                return CSSSelector(value.lower()) # selectors 
            except AssertionError as e:
                raise FieldValidationException("The value of '%s' for the '%s' parameter is not a valid selector: %s" % (str(value), name, str(e)))
    
    def to_python(self, value):
        Field.to_python(self, value)
        
        return SelectorField.parse_selector(value, self.name)
    
    def to_string(self, value):
        return value.css

class Timer(object):
    """
    This class is used to time durations.
    """
    
    def __init__(self, verbose=False):
        self.verbose = verbose

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        self.end = time.time()
        self.secs = self.end - self.start
        self.msecs = self.secs * 1000  # millisecs

class WebsiteInputConfig(SplunkAppObjModel):
    
    resource       = '/admin/app_website_input'
    proxy_server   = ModelField()
    proxy_port     = ModelIntField()
    proxy_type     = ModelField()
    proxy_user     = ModelField()
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
    
    SUPPORTED_BROWSERS= [INTEGRATED_CLIENT, FIREFOX]
    
    def __init__(self, timeout=30, **kwargs):

        scheme_args = {'title': "Web-pages",
                       'description': "Retrieve information from web-pages",
                       'use_external_validation': "true",
                       'streaming_mode': "xml",
                       'use_single_instance': "true"}
        
        args = [
                Field("title", "Title", "A short description (typically just the domain name)", empty_allowed=False),
                URLField("url", "URL", "The URL to connect to (must be be either HTTP or HTTPS protocol)", empty_allowed=False),
                DurationField("interval", "Interval", "The interval defining how often to perform the check; can include time units (e.g. 15m for 15 minutes, 8h for 8 hours)", empty_allowed=False),
                SelectorField("selector", "Selector", "A selector that will match the data you want to retrieve", none_allowed=True, empty_allowed=True),
                Field("username", "Username", "The username to use for authenticating (only HTTP authentication supported)", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                Field("password", "Password", "The password to use for authenticating (only HTTP authentication supported)", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                ListField("name_attributes", "Field Name Attributes", "A list of attributes to use for assigning a field name", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                Field("user_agent", "User Agent", "The user-agent to use when communicating with the server", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                BooleanField("use_element_name", "Use Element Name as Field Name", "Use the element's tag name as the field name", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                IntegerField("page_limit", "Discovered page limit", "A limit on the number of pages that will be auto-discovered", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                IntegerField("depth_limit", "Depth limit", "A limit on how many levels deep the search for pages will go", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                Field("url_filter", "URL Filter", "A wild-card that will indicate which pages it should search for matches in", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                BooleanField("raw_content", "Raw content", "Return the raw content returned by the server", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                Field("text_separator", "Text Separator", 'A string that will be placed between the extracted values (e.g. a separator of ":" for a match against "<a>tree</a><a>frog</a>" would return "tree:frog")', none_allowed=True, empty_allowed=True),
                Field("browser", "Browser", 'The browser to use', none_allowed=True, empty_allowed=True),
                IntegerField("timeout", "Timeout", 'The timeout (in number of seconds)', none_allowed=True, empty_allowed=True),
                BooleanField("output_as_mv", "Output as Multi-value Field", "Output the matches as multi-value field", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                ]
        
        ModularInput.__init__( self, scheme_args, args )
        
        if timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 30
    
    @classmethod
    def get_file_path( cls, checkpoint_dir, stanza ):
        """
        Get the path to the checkpoint file.
        
        Arguments:
        checkpoint_dir -- The directory where checkpoints ought to be saved
        stanza -- The stanza of the input being used
        """
        
        return os.path.join( checkpoint_dir, hashlib.md5(stanza).hexdigest() + ".json" )
       
    @classmethod
    def add_auth_to_url(cls, url, username, password):
        """
        Add the username and password to the URL. For example, convert http://test.com to http://admin:opensesame@test.com.
        
        Arguments:
        url -- A string version of the URL
        username -- The username
        password -- The password
        """
        
        if username is not None and password is not None and username != "" and password != "":
            
            # Split up the URL
            u = urlsplit(url)
            
            # Now, build a new URL with the new username and password
            split = []
            
            for item in (u[:]):
                split.append(item)
            
            # Replace the netloc with one that contains the username and password. Note that this will drop the existing username and password if it exists
            if u.port is None: #(u.port == 80 and u.scheme == "http") or (u.port == 443 and u.scheme == "https"):
                split[1] = username + ":" + password + "@" + u.hostname
            else:
                split[1] = username + ":" + password + "@" + u.hostname + ":" + str(u.port)
                
            return urlunsplit(split)
            
            #return re.sub("://", "://" + username + ":" + password + "@", url, 1)
        else:
            return url
       
    @classmethod
    def append_if_not_empty(cls, str1, str2, separator):
        """
        
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
            
        if len(str1) > 0 and len(str2) > 0:
            return str1 + separator + str2
        if len(str1) > 0:
            return str1
        if len(str2) > 0:
            return str2
        else:
            return ""
            
       
    @classmethod
    def get_text(cls, element, text_separator=" "):
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
            text = ""
        
        # Iterate through the child nodes and add up the text
        for child_element in element:
            
            text = cls.append_if_not_empty(text, WebInput.get_text(child_element), text_separator)
            
            # Get the tail text
            if child_element.tail:
                tail_text = child_element.tail.strip()
                
                text = cls.append_if_not_empty(text, tail_text, text_separator)
            
        return text.strip()
       
    @classmethod
    def escape_field_name(cls, name):
        name = re.sub(r'[^A-Z0-9]', '_', name.strip(), flags=re.IGNORECASE)
        
        if len(name) == 0:
            return "blank"
        
        if name in cls.RESERVED_FIELD_NAMES:
            return "match_" + name
        
        return name
        
    @classmethod
    def resolve_proxy_type(cls, proxy_type):
        
        # Make sure the proxy string is not none
        if proxy_type is None:
            return None
        
        # Prepare the string so that the proxy type can be matched more reliably
        t = proxy_type.strip().lower()
        
        if t == "socks4":
            return socks.PROXY_TYPE_SOCKS4
        elif t == "socks5":
            return socks.PROXY_TYPE_SOCKS5
        elif t == "http":
            return socks.PROXY_TYPE_HTTP
        elif t == "":
            return None
        else:
            logger.warn("Proxy type is not recognized: %s", proxy_type)
            return None
    
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
            find_meta_charset = re.compile("<meta(?!\s*(?:name|value)\s*=)[^>]*?charset\s*=[\s\"']*([^\s\"'/>]*)", re.IGNORECASE) #http://stackoverflow.com/questions/3458217/how-to-use-regular-expression-to-match-the-charset-string-in-html
            matched_encoding = find_meta_charset.search(content)
                
            if matched_encoding:
                encoding = matched_encoding.groups()[0]
            
        # Try getting the encoding from the content-type header
        if encoding is None and charset_detect_content_type_header_enabled:
            
            if response is not None and 'content-type' in response:
                find_header_charset = re.compile("charset=(.*)",re.IGNORECASE)
                matched_encoding = find_header_charset.search(response['content-type'])
                
                if matched_encoding:
                    encoding = matched_encoding.groups()[0]
            
        # Try sniffing the encoding
        if encoding is None and charset_detect_sniff_enabled:
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
        
        r = re.escape(wildcard)
        return r.replace('\*', ".*")
    
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
    def extract_links(cls, lxml_html_tree, source_url, links=None, url_filter=None):
        """
        Get the results from performing a HTTP request and parsing the output.
        
        Arguments:
        lxml_html_tree -- A parsed XML tree.
        source_url -- The url from which the content came from; this should be a string.
        links -- An array to put the links into
        url_filter -- The URL to filter extraction to (a wild-card as a string)
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
                if link not in links and cls.is_url_in_url_filter(link, url_filter): #cls.is_url_in_domain(source_url, domain_limit):
                    links.append(link)
        
        return links
    
    @classmethod
    def get_result_built_in_client(cls, http, url, headers, charset_detect_meta_enabled=True, charset_detect_content_type_header_enabled=True, charset_detect_sniff_enabled=True):
        
        response, content = http.request( url.geturl(), 'GET', headers=headers)
        
        encoding = cls.detect_encoding(content, response, charset_detect_meta_enabled, charset_detect_content_type_header_enabled, charset_detect_sniff_enabled)
        
        return response.status, content, encoding
    
    @classmethod
    def get_firefox_profile(cls, proxy_type="http", proxy_server=None, proxy_port=None, proxy_user=None, proxy_password=None):
        profile = webdriver.FirefoxProfile()
        
        # This is necessary in order to avoid the dialog that FireFox uses to stop potential phishing attacks that use credentials encoded in the URL
        # See http://lukemurphey.net/issues/1658
        profile.set_preference('network.http.phishy-userpass-length', 255)
        
        # Return none if no proxy is defined
        if proxy_server is None or proxy_port is None:
            pass
        
        # Use a socks proxy
        elif proxy_type == "socks4" or proxy_type == "socks5":
            profile.set_preference('network.proxy.type', 1)
            profile.set_preference('network.proxy.socks', proxy_server)
            profile.set_preference('network.proxy.socks_port', int(proxy_port))
            
        # Use an HTTP proxy
        elif proxy_type == "http":
            
            profile.set_preference('network.proxy.type', 1)
            profile.set_preference('network.proxy.http', proxy_server)
            profile.set_preference('network.proxy.http_port', int(proxy_port)) 
            profile.set_preference('network.proxy.ssl', proxy_server)
            profile.set_preference('network.proxy.ssl_port', int(proxy_port)) 
            
        return profile
    
    @classmethod
    def add_browser_driver_to_path(cls):
        
        driver_path = None
        
        if sys.platform == "linux2" and platform.architecture()[0] == '64bit':
            driver_path = "linux64"
        elif sys.platform == "linux2":
            driver_path = "linux32"
        else:
            driver_path = sys.platform
        
        full_driver_path = os.path.join(get_apps_dir(), "website_input", "bin", "browser_drivers", driver_path)
        
        if not full_driver_path in os.environ["PATH"]:
            os.environ["PATH"] += ":" +full_driver_path
            logger.debug("Updating path to include selenium driver path=%s, working_path=%s", full_driver_path, os.getcwd())
    
    @classmethod
    def get_result_browser(cls, url, browser="firefox", sleep_seconds=5, username=None, password=None, proxy_type="http", proxy_server=None, proxy_port=None, proxy_user=None, proxy_password=None):
        
        # Update the path if necessary so that the drivers can be found
        WebInput.add_browser_driver_to_path()
        
        driver = None
        logger.debug("Attempting to get content using browser=%s", browser)
        
        try:
            # Assign a default argument for browser
            if browser is None:
                browser = cls.FIREFOX
            else: 
                browser = browser.lower().strip()
            
            # Make the browser
            if browser == cls.FIREFOX:
                
                # Start a display so that this works on headless hosts
                if not os.name == 'nt':
                    try:
                        display = Display(visible=0, size=(800, 600))
                        display.start()
                    except EasyProcessCheckInstalledError:
                        logger.warn("Failed to load the virtual display; Firefox might not be able to run if this is a headless host")
                    except Exception:
                        logger.exception("Failed to load the virtual display; Firefox might not be able to run if this is a headless host")
                
                profile = cls.get_firefox_profile(proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)
                
                if profile is not None:
                    logger.info("Using a proxy with Firefox")
                    driver = webdriver.Firefox(profile, log_path=make_splunkhome_path(['var', 'log', 'splunk', 'geckodriver.log']))
                else:
                    driver = webdriver.Firefox(log_path=make_splunkhome_path(['var', 'log', 'splunk', 'geckodriver.log']))
            else:
                raise Exception("Browser '%s' not recognized" % (browser))
            
            # Load the page
            driver.get(cls.add_auth_to_url(url.geturl(), username, password))
            """
            driver.get(url.geturl())
            
            if username is not None and password is not None: 
                wait = WebDriverWait(driver, 10)
                time.sleep(2)
                alert = wait.until(expected_conditions.alert_is_present())
                alert.authenticate(username, password)
            """
            
            
            # Wait for the content to load
            time.sleep(sleep_seconds)
            
            # Get the content
            content = driver.execute_script("return document.documentElement.outerHTML")
            
            return content
        finally:
            if driver is not None:
                driver.quit()
    
    @classmethod
    def get_result_single(cls, http, url, selector, headers, name_attributes=[], output_matches_as_mv=True, output_matches_as_separate_fields=False, charset_detect_meta_enabled=True, charset_detect_content_type_header_enabled=True, charset_detect_sniff_enabled=True, include_empty_matches=False, use_element_name=False, extracted_links=None, url_filter=None, source_url_depth=0, include_raw_content=False, text_separator=None, browser=None, timeout=5, username=None, password=None, proxy_type="http", proxy_server=None, proxy_port=None, proxy_user=None, proxy_password=None, additional_fields=None, match_prefix=None):
        """
        Get the results from performing a HTTP request and parsing the output.
        
        Arguments:
        http -- The HTTP object to perform the request with
        url -- The url to connect to. This object ought to be an instance derived from using urlparse
        selector -- A CSS selector that matches the data to retrieve
        headers -- The HTTP headers
        name_attributes -- Attributes to use the values for assigning the names
        output_matches_as_mv -- Output all of the matches with the same name ("match")
        output_matches_as_separate_fields -- Output all of the matches as separate fields ("match1", "match2", etc.)
        charset_detect_meta_enabled -- Enable detection from the META attribute in the head tag
        charset_detect_content_type_header_enabled -- Enable detection from the content-type header
        charset_detect_sniff_enabled -- Enable detection by reviewing some of the content and trying different encodings
        include_empty_matches -- Output matches that result in empty strings
        use_element_name -- Use the element as the field name
        extracted_links -- The array to place the extract links (will only be done if not None)
        url_filter -- The wild-card to filter extracted URLs to
        source_url_depth -- The depth level of the URL from which this URL was discovered from. This is used for tracking how depth the crawler should go.
        include_raw_content -- Include the raw content (if true, the 'content' field will include the raw content)
        text_separator -- The content to put between each text node that matches within a given selector
        browser -- The browser to use
        timeout -- The timeout to use for waiting for content via the browser
        username -- The username to use for authentication
        password -- The username to use for authentication
        proxy_type -- The type of proxy server (defaults to "http")
        proxy_server -- The IP or domain name of the proxy server
        proxy_port -- The port that the proxy server runs on
        proxy_user -- The user name of the proxy server account
        proxy_password -- The password of the proxy server account
        additional_fields -- Additional fields to put into the result set
        match_prefix -- A prefix to attach to prepend to the front of the match fields
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
            with Timer() as timer:
                
                response_code, content, encoding = cls.get_result_built_in_client( http, url, headers, charset_detect_meta_enabled, charset_detect_content_type_header_enabled, charset_detect_sniff_enabled)
                result['browser'] = cls.INTEGRATED_CLIENT
                
            # Get the content via the browser too if requested
            # Note that we already got the content via the internal client. This was necessary because web-driver doesn't give us the response code
            if browser is not None and browser.strip() != cls.INTEGRATED_CLIENT:
                try:
                    content = cls.get_result_browser(url, browser, timeout, username, password, proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)
                    result['browser'] = browser
                except:
                    logger.exception("Unable to get the content using the browser=%s", browser)
                
            # Get the size of the content
            result['response_size'] = len(content)
            
            # Retrieve the meta-data
            result['response_code'] = response_code   
            result['request_time'] = timer.msecs
            result['url'] = url.geturl()
            
            # Get the hash of the content
            result['content_md5'] = hashlib.md5(content).hexdigest()
            result['content_sha224'] = hashlib.sha224(content).hexdigest()
            
            # Store the encoding in the result
            result['encoding'] = encoding
            
            # Decode the content
            content_decoded = content.decode(encoding=encoding, errors='replace')
            
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
                    match_text = cls.unescape(WebInput.get_text(match, text_separator))
                    
                    # Don't include the field if it is empty
                    if include_empty_matches or len(match_text) > 0:
                        
                        # Keep a count of how many fields we matched
                        fields_included = fields_included + 1
                        
                        # Save the match
                        field_made = False
                        
                        # Try to use the name attributes for determining the field name
                        for a in name_attributes:
                            
                            attributes = dict(match.attrib)
                            
                            if a in attributes:
                                
                                field_made = True
                                field_name = cls.escape_field_name(attributes[a])
                                
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
                    
                    for extracted in cls.extract_links(tree, url.geturl(), url_filter=url_filter):
                        
                        # Add the extracted link if it is not already in the list
                        if extracted not in extracted_links:
                            
                            # Add the discovered URL (with the appropriate depth)
                            extracted_links[extracted] = DiscoveredURL(source_url_depth + 1)
                else:
                    logger.debug("Not extracting links since extracted_links is None")
        
        # Handle time outs    
        except socket.timeout:
            
            # Note that the connection timed out    
            result['timed_out'] = True
            
        except socket.error as e:
            
            if e.errno in [60, 61]:
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
    
    @classmethod
    def get_http_client(cls, username=None, password=None, timeout=30, proxy_type="http", proxy_server=None, proxy_port=None, proxy_user=None, proxy_password=None):
        """
        Retrieve data from a website.
        
        Arguments:
        username -- The username to use for authentication
        password -- The username to use for authentication
        proxy_type -- The type of proxy server (defaults to "http")
        proxy_server -- The IP or domain name of the proxy server
        proxy_port -- The port that the proxy server runs on
        proxy_user -- The user name of the proxy server account
        proxy_password -- The password of the proxy server account
        user_agent -- The string to use for the user-agent
        """
        
        # Determine which type of proxy is to be used (if any)
        resolved_proxy_type = cls.resolve_proxy_type(proxy_type)
            
        # Setup the proxy info if so configured
        if resolved_proxy_type is not None and proxy_server is not None and len(proxy_server.strip()) > 0:
            proxy_info = httplib2.ProxyInfo(resolved_proxy_type, proxy_server, proxy_port, proxy_user=proxy_user, proxy_pass=proxy_password)
            logger.info('Using a proxy server, type=%s, proxy_server="%s"', resolved_proxy_type, proxy_server)
        else:
            # No proxy is being used
            proxy_info = None
            logger.info("Not using a proxy server")
                        
        # Make the HTTP object
        http = httplib2.Http(proxy_info=proxy_info, timeout=timeout, disable_ssl_certificate_validation=True)
        
        # Setup the credentials if necessary
        if username is not None or password is not None:
                
            if username is None:
                username = ""
                    
            if password is None:
                password = ""
                    
            http.add_credentials(username, password)
        
        # Return the client
        return http
    
    @classmethod
    def scrape_page(cls, url, selector, username=None, password=None, timeout=30, name_attributes=[], output_matches_as_mv=True, output_matches_as_separate_fields=False, charset_detect_meta_enabled=True, charset_detect_content_type_header_enabled=True, charset_detect_sniff_enabled=True, include_empty_matches=False, proxy_type="http", proxy_server=None, proxy_port=None, proxy_user=None, proxy_password=None, user_agent=None, use_element_name=False, page_limit=1, depth_limit=50, url_filter=None, include_raw_content=False, text_separator=None, browser=None, additional_fields=None, match_prefix=None):
        """
        Retrieve data from a website.
        
        Arguments:
        url -- The url to connect to. This object ought to be an instance derived from using urlparse
        selector -- A CSS selector that matches the data to retrieve
        username -- The username to use for authentication
        password -- The username to use for authentication
        timeout -- The amount of time to quit waiting on a connection
        name_attributes -- Attributes to use the values for assigning the names
        output_matches_as_mv -- Output all of the matches with the same name ("match")
        output_matches_as_separate_fields -- Output all of the matches as separate fields ("match1", "match2", etc.)
        charset_detect_meta_enabled -- Enable detection from the META attribute in the head tag
        charset_detect_content_type_header_enabled -- Enable detection from the content-type header
        charset_detect_sniff_enabled -- Enable detection by reviewing some of the content and trying different encodings
        include_empty_matches -- Output matches that result in empty strings
        proxy_type -- The type of proxy server (defaults to "http")
        proxy_server -- The IP or domain name of the proxy server
        proxy_port -- The port that the proxy server runs on
        proxy_user -- The user name of the proxy server account
        proxy_password -- The password of the proxy server account
        user_agent -- The string to use for the user-agent
        use_element_name -- Use the element as the field name
        page_limit -- The page of pages to limit matches to
        depth_limit == The limit on the depth of URLs found
        url_filter -- A wild-card to limit the extracted URLs to
        include_raw_content -- Include the raw content (if true, the 'content' field will include the raw content)
        text_separator -- The content to put between each text node that matches within a given selector
        browser -- The browser to use
        additional_fields -- Additional fields to put into the result set
        match_prefix -- A prefix to attach to prepend to the front of the match fields
        """
        
        if isinstance(url, basestring):
            url = URLField.parse_url(url, "url")
            
        if isinstance(selector, basestring):
            selector = SelectorField.parse_selector(selector, "selector")
        
        logger.info('Running web input, url="%s"', url.geturl())
        
        results = []
        
        try:
            # Determine which type of proxy is to be used (if any)
            resolved_proxy_type = cls.resolve_proxy_type(proxy_type)
            
            # Setup the proxy info if so configured
            if resolved_proxy_type is not None and proxy_server is not None and len(proxy_server.strip()) > 0:
                proxy_info = httplib2.ProxyInfo(resolved_proxy_type, proxy_server, proxy_port, proxy_user=proxy_user, proxy_pass=proxy_password)
                logger.info('Using a proxy server, type=%s, proxy_server="%s"', resolved_proxy_type, proxy_server)
            else:
                # No proxy is being used
                proxy_info = None
                logger.info("Not using a proxy server")
                        
            # Make the HTTP object
            http = httplib2.Http(proxy_info=proxy_info, timeout=timeout, disable_ssl_certificate_validation=True)
            
            # Setup the credentials if necessary
            if username is not None or password is not None:
                
                if username is None:
                    username = ""
                    
                if password is None:
                    password = ""
                    
                http.add_credentials(username, password)
            
            # Setup the headers as necessary
            headers = {}
            
            if user_agent is not None:
                logger.info("Setting user-agent=%s", user_agent)
                headers['User-Agent'] = user_agent
                        
            # Run the scraper and get the results
            extracted_links = OrderedDict()
            extracted_links[url.geturl()] = DiscoveredURL(0)

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
                    logger.info("No more URLs in the list to process")
                    break
                
                # Make the keyword argument list
                kw = {
                        'url_filter' : url_filter,
                        'source_url_depth': source_url_depth,
                        'include_raw_content': include_raw_content,
                        'text_separator': text_separator,
                        'timeout':timeout,
                        'browser': browser,
                        'proxy_type': proxy_type,
                        'proxy_server': proxy_server,
                        'proxy_port': proxy_port,
                        'proxy_user': proxy_user,
                        'proxy_password': proxy_password,
                        'extracted_links': extracted_links,
                        'match_prefix': match_prefix
                      }
                
                # Don't have the function extract URLs if the depth limit has been reached
                if source_url_depth >= depth_limit:
                    kw['extracted_links'] = None
                
                # Perform the scrape
                result = cls.get_result_single(http, urlparse(url), selector, headers, name_attributes, output_matches_as_mv, output_matches_as_separate_fields, charset_detect_meta_enabled, charset_detect_content_type_header_enabled, charset_detect_sniff_enabled, include_empty_matches, use_element_name, additional_fields=additional_fields, **kw)
                
                # Append the result
                if result is not None:
                    results.append(result)
                
        except Exception:
            logger.exception("A general exception was thrown when executing a web request") # TODO: remove this one or the one in get_result_single() 
            raise
        
        return results
    
    @classmethod
    def unescape(cls, text):
        """
        Removes HTML or XML character references and entities from a text string. Return the plain text, as a Unicode string, if necessary.
        
        Argument:
        text -- The HTML (or XML) source text.
        """
        
        import HTMLParser
        h = HTMLParser.HTMLParser()
        
        return h.unescape(text)
    
    def get_proxy_config(self, session_key, stanza="default"):
        """
        Get the proxy configuration
        
        Arguments:
        session_key -- The session key to use when connecting to the REST API
        stanza -- The stanza to get the proxy information from (defaults to "default")
        """
        
        # If the stanza is empty, then just use the default
        if stanza is None or stanza.strip() == "":
            stanza = "default"
        
        # Get the proxy configuration
        try:
            website_input_config = WebsiteInputConfig.get( WebsiteInputConfig.build_id( stanza, "website_input", "nobody"), sessionKey=session_key )
            
            logger.info("Proxy information loaded, stanza=%s", stanza)
            
        except splunk.ResourceNotFound:
            logger.error('Unable to find the proxy configuration for the specified configuration stanza=%s, error="not found"', stanza)
            raise
        except splunk.SplunkdConnectionException:
            logger.error('Unable to find the proxy configuration for the specified configuration stanza=%s error="splunkd connection error"', stanza)
            raise
        
        return website_input_config.proxy_type, website_input_config.proxy_server, website_input_config.proxy_port, website_input_config.proxy_user, website_input_config.proxy_password
        
    
    def run(self, stanza, cleaned_params, input_config):
        
        # Make the parameters
        interval         = cleaned_params["interval"]
        title            = cleaned_params["title"]
        url              = cleaned_params["url"]
        selector         = cleaned_params.get("selector", None)
        username         = cleaned_params.get("username", None)
        password         = cleaned_params.get("password", None)
        name_attributes  = cleaned_params.get("name_attributes", [])
        user_agent       = cleaned_params.get("user_agent", None)
        timeout          = cleaned_params.get("timeout", self.timeout)
        sourcetype       = cleaned_params.get("sourcetype", "web_input")
        host             = cleaned_params.get("host", None)
        index            = cleaned_params.get("index", "default")
        conf_stanza      = cleaned_params.get("configuration", None)
        use_element_name = cleaned_params.get("use_element_name", False)
        page_limit       = cleaned_params.get("page_limit", 1)
        url_filter       = cleaned_params.get("url_filter", None)
        depth_limit      = cleaned_params.get("depth_limit", 25)
        raw_content      = cleaned_params.get("raw_content", False)
        text_separator   = cleaned_params.get("text_separator", " ")
        browser          = cleaned_params.get("browser", self.INTEGRATED_CLIENT)
        output_as_mv     = cleaned_params.get("output_as_mv", True)
        source           = stanza
        
        if self.needs_another_run( input_config.checkpoint_dir, stanza, interval ):
            
            # Get the proxy configuration
            try:
                proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = self.get_proxy_config(input_config.session_key, conf_stanza)
            except splunk.ResourceNotFound:
                logger.error("The proxy configuration could not be loaded (resource not found). The execution will be skipped for now for this input with stanza=%s", stanza)
                return
            except splunk.SplunkdConnectionException:
                logger.error("The proxy configuration could not be loaded (splunkd connection problem). The execution will be skipped for now for this input with stanza=%s", stanza)
                return
            
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
                
                result = WebInput.scrape_page(url, selector, username, password, timeout, name_attributes, proxy_type=proxy_type, proxy_server=proxy_server, proxy_port=proxy_port, proxy_user=proxy_user, proxy_password=proxy_password, user_agent=user_agent, use_element_name=use_element_name, page_limit=page_limit, depth_limit=depth_limit, url_filter=url_filter, include_raw_content=raw_content, text_separator=text_separator, browser=browser, output_matches_as_mv=output_matches_as_mv, output_matches_as_separate_fields=output_matches_as_separate_fields, additional_fields=additional_fields)
                
                matches = 0
                
                if result:
                    matches = len(result)
                else:
                    logger.debug("No match returned in the result")
                
                logger.info("Successfully executed the website input, matches_count=%r, stanza=%s, url=%s", matches, stanza, url.geturl())
            except Exception:
                logger.exception("An exception occurred when attempting to retrieve information from the web-page, stanza=%s", stanza) 
            
            # Process the result (if we got one)
            if result is not None:
                
                # Process each event
                for r in result:
                    
                    # Send the event
                    if self.OUTPUT_USING_STASH:
                    
                        # Write the event as a stash new file
                        writer = StashNewWriter(index=index, source_name=source, file_extension=".stash_web_input", sourcetype=sourcetype)
                        logger.info("Wrote stash file=%s", writer.write_event(r))
                        
                    else:
                        
                        # Write the event using the built-in modular input method
                        self.output_event(r, stanza, index=index, source=source, sourcetype=sourcetype, host=host, unbroken=True, close=True, encapsulate_value_in_double_quotes=True)

                    
                # Get the time that the input last ran
                last_ran = self.last_ran(input_config.checkpoint_dir, stanza)
                
                # Save the checkpoint so that we remember when we last executed this
                self.save_checkpoint_data(input_config.checkpoint_dir, stanza, { 'last_run' : self.get_non_deviated_last_run(last_ran, interval, stanza) })
        
            
if __name__ == '__main__':
    try:
        web_input = WebInput()
        web_input.execute()
        sys.exit(0)
    except Exception:
        logger.exception("Unhandled exception was caught, this may be due to a defect in the script") # This logs general exceptions that would have been unhandled otherwise (such as coding errors)
        raise