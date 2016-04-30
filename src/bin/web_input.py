
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from website_input_app.modular_input import Field, ListField, FieldValidationException, ModularInput, URLField, DurationField, BooleanField
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
import re
from urlparse import urljoin

import httplib2
from httplib2 import socks
import lxml.html

from cssselector import CSSSelector

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

class WebInput(ModularInput):
    """
    The web input modular input connects to a web-page obtains information from it.
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
                SelectorField("selector", "Selector", "A selector that will match the data you want to retrieve", none_allowed=False, empty_allowed=False),
                Field("username", "Username", "The username to use for authenticating (only HTTP authentication supported)", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                Field("password", "Password", "The password to use for authenticating (only HTTP authentication supported)", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                ListField("name_attributes", "Field Name Attributes", "A list of attributes to use for assigning a field name", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                Field("user_agent", "User Agent", "The user-agent to use when communicating with the server", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
                BooleanField("use_element_name", "Use Element Name as Field Name", "Use the element's tag name as the field name", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False)
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
    def get_text(cls, element):
        """
        Get the accumulated text from the child nodes.
        
        Arguments:
        element -- The element to get the text from
        """
        
        if element.text is not None:
            text = element.text.strip()
        else:
            text = ""
        
        # Iterate through the child nodes and add up the text
        for child_element in element:
            text = text + " " + WebInput.get_text(child_element)
            
            # Get the tail text
            if child_element.tail:
                tail_text = child_element.tail.strip()
                
                if len(tail_text) > 0:
                    text = text + " " + tail_text
            
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
            
            if 'content-type' in response:
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
    def remove_anchor(cls, link):
        m = re.search('([^#]*).*', link)
        return m.group(1)
    
    @classmethod
    def cleanup_link(cls, source_link, link):
        return cls.remove_anchor(urljoin(source_link, link))
    
    @classmethod
    def extract_links(cls, lxml_html_tree, links=None):
        
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
                link = cls.cleanup_link(attributes['href'])
                
                # MAke sure the link wasn't already in the list
                if link not in links:
                    links.append(link)
        
        return links
    
    @classmethod
    def scrape_page(cls, url, selector, username=None, password=None, timeout=30, name_attributes=[], output_matches_as_mv=True, output_matches_as_separate_fields=False, charset_detect_meta_enabled=True, charset_detect_content_type_header_enabled=True, charset_detect_sniff_enabled=True, include_empty_matches=False, proxy_type="http", proxy_server=None, proxy_port=None, proxy_user=None, proxy_password=None, user_agent=None, use_element_name=False):
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
        """
        
        if isinstance(url, basestring):
            url = URLField.parse_url(url, "url")
            
        if isinstance(selector, basestring):
            selector = SelectorField.parse_selector(selector, "selector")
        
        logger.debug('Running web input, url="%s"', url.geturl())
        
        try:
            # Determine which type of proxy is to be used (if any)
            resolved_proxy_type = cls.resolve_proxy_type(proxy_type)
            
            # Setup the proxy info if so configured
            if resolved_proxy_type is not None and proxy_server is not None and len(proxy_server.strip()) > 0:
                proxy_info = httplib2.ProxyInfo(resolved_proxy_type, proxy_server, proxy_port, proxy_user=proxy_user, proxy_pass=proxy_password)
                logger.debug('Using a proxy server, type=%s, proxy_server="%s"', resolved_proxy_type, proxy_server)
            else:
                # No proxy is being used
                proxy_info = None
                logger.debug("Not using a proxy server")
                        
            # Make the HTTP object
            http = httplib2.Http(proxy_info=proxy_info, timeout=timeout, disable_ssl_certificate_validation=True)
            
            # Setup the credentials if necessary
            if username is not None or password is not None:
                
                if username is None:
                    username = ""
                    
                if password is None:
                    password = ""
                    
                http.add_credentials(username, password)
                
            # This will be where the result information will be stored
            result = {}
            
            # Setup the headers as necessary
            headers = {}
            
            if user_agent is not None:
                logger.info("Setting user-agent=%s", user_agent)
                headers['User-Agent'] = user_agent
                        
            # Perform the request
            with Timer() as timer:
                
                response, content = http.request( url.geturl(), 'GET', headers=headers)
                
                # Get the hash of the content
                response_md5 = hashlib.md5(content).hexdigest()
                response_sha224 = hashlib.sha224(content).hexdigest()
                
                # Get the size of the content
                result['response_size'] = len(content)
            
            # Retrieve the meta-data
            result['response_code'] = response.status    
            result['request_time'] = timer.msecs
            
            # Determine the encoding
            encoding = cls.detect_encoding(content, response, charset_detect_meta_enabled, charset_detect_content_type_header_enabled, charset_detect_sniff_enabled)
            
            # Store the encoding in the result
            result['encoding'] = encoding
            
            # Decode the content
            content_decoded = content.decode(encoding=encoding, errors='replace')
            
            # Parse the HTML
            try:
                tree = lxml.html.fromstring(content_decoded)
            except ValueError:
                # lxml will refuse to parse a Unicode string containing XML that declares the encoding even if the encoding declaration matches the encoding used.
                # This is odd since this exception will be thrown even though the app successfully determined the encoding (it matches the declaration in the XML).
                # The app handles this by attempting to parse the content a second time if it failed when using Unicode. This is necessary because I cannot allow
                # lxml to discover the encoding on its own since it doesn't know what the HTTP headers are and cannot sniff the encoding as well as the input does
                # (which uses several methods to determine the encoding).
                logger.debug('The content is going to be parsed without decoding because the parser refused to parse it with encoding (http://goo.gl/4GRjJF), url="%s"', url.geturl())
                tree = lxml.html.fromstring(content)
            
            # Apply the selector to the DOM tree
            matches = selector(tree)
            
            # Get the text from matching nodes
            if output_matches_as_mv:
                result['match'] = []
                
            # We are going to count how many fields we made
            fields_included = 0
            
            # Store the raw match count (the nodes that the CSS matches)
            result['raw_match_count'] = len(matches)
            
            for match in matches:
                
                # Unescape the text in case it includes HTML entities
                match_text = cls.unescape(WebInput.get_text(match))
                
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
                            
                            # If the field does not exists, create it
                            if not field_name in result and output_matches_as_mv:
                                result[field_name] = [match_text]
                                
                            # If the field exists and we are adding them as mv, then add it
                            elif field_name in result and output_matches_as_mv:
                                result[field_name].append(match_text)
                                
                            # Otherwise, output it as a separate field
                            if output_matches_as_separate_fields:
                                result['match_' + field_name + "_" + str(fields_included)] = match_text
                                
                    # Try to use the name of the element
                    if use_element_name and not field_made:
                        
                        # If the field does not exists, create it
                        if not match.tag in result and output_matches_as_mv:
                            result[match.tag] = [match_text]
                        
                        # If the field exists and we are adding them as mv, then add it
                        elif output_matches_as_mv:
                            result[match.tag].append(match_text)
                        
                        # Otherwise, output it as a separate field
                        if output_matches_as_separate_fields:
                            result['match_' + match.tag] = match_text
                        
                    # Otherwise, output the fields as generic fields
                    if not field_made:
                        
                        if output_matches_as_mv:
                            result['match'].append(match_text) # Note: the 'match' in the dictionary will already be populated
                        
                        if output_matches_as_separate_fields:
                            result['match_' + str(fields_included)] = match_text
        
        # Handle time outs    
        except socket.timeout:
            
            # Note that the connection timed out    
            result['timed_out'] = True
            
        except socket.error as e:
            
            if e.errno in [60, 61]:
                result['timed_out'] = True
        
        except Exception as e:
            logger.exception("A general exception was thrown when executing a web request")
            raise
        
        return result
    
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
            
            logger.debug("Proxy information loaded, stanza=%s", stanza)
            
        except splunk.ResourceNotFound:
            logger.error("Unable to find the proxy configuration for the specified configuration stanza=%s", stanza)
            raise
        except splunk.SplunkdConnectionException:
            logger.error("Unable to find the proxy configuration for the specified configuration stanza=%s", stanza)
            raise
        
        return website_input_config.proxy_type, website_input_config.proxy_server, website_input_config.proxy_port, website_input_config.proxy_user, website_input_config.proxy_password
        
    
    def run(self, stanza, cleaned_params, input_config):
        
        # Make the parameters
        interval         = cleaned_params["interval"]
        title            = cleaned_params["title"]
        url              = cleaned_params["url"]
        selector         = cleaned_params["selector"]
        username         = cleaned_params.get("username", None)
        password         = cleaned_params.get("password", None)
        name_attributes  = cleaned_params.get("name_attributes", [])
        user_agent       = cleaned_params.get("user_agent", None)
        timeout          = self.timeout
        sourcetype       = cleaned_params.get("sourcetype", "web_input")
        host             = cleaned_params.get("host", None)
        index            = cleaned_params.get("index", "default")
        conf_stanza      = cleaned_params.get("configuration", None)
        use_element_name = cleaned_params.get("use_element_name", False)
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
                result = WebInput.scrape_page(url, selector, username, password, timeout, name_attributes, proxy_type=proxy_type, proxy_server=proxy_server, proxy_port=proxy_port, proxy_user=proxy_user, proxy_password=proxy_password, user_agent=user_agent, use_element_name=use_element_name)
                
                matches = 0
                
                if 'match' in result:
                    matches = len(result['match'])
                
                logger.info("Successfully executed the website input, matches_count=%r, stanza=%s, url=%s", matches, stanza, url.geturl())
            except Exception:
                logger.exception("An exception occurred when attempting to retrieve information from the web-page") 
            
            # Process the result (if we got one)
            if result is not None:
                
                # Send the event
                self.output_event(result, stanza, index=index, source=source, sourcetype=sourcetype, host=host, unbroken=True, close=True, encapsulate_value_in_double_quotes=True)
            
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