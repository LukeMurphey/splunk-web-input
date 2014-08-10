
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from website_input_app.modular_input import Field, ListField, FieldValidationException, ModularInput

import logging
from logging import handlers
import hashlib
import socket
import json
from urlparse import urlparse
import sys
import time
import os
import splunk
import chardet
import re

import httplib2
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

class URLField(Field):
    """
    Represents a URL. The URL is converted to a Python object that was created via urlparse.
    """
    
    @classmethod
    def parse_url(cls, value, name):
        parsed_value = urlparse(value)
        
        if parsed_value.hostname is None or len(parsed_value.hostname) <= 0:
            raise FieldValidationException("The value of '%s' for the '%s' parameter does not contain a host name" % (str(value), name))
        
        if parsed_value.scheme not in ["http", "https"]:
            raise FieldValidationException("The value of '%s' for the '%s' parameter does not contain a valid protocol (only http and https are supported)" % (str(value), name))
    
        return parsed_value
    
    def to_python(self, value):
        Field.to_python(self, value)
        
        return URLField.parse_url(value, self.name)
    
    def to_string(self, value):
        return value.geturl()

class DurationField(Field):
    """
    The duration field represents a duration as represented by a string such as 1d for a 24 hour period.
    
    The string is converted to an integer indicating the number of seconds.
    """
    
    DURATION_RE = re.compile("(?P<duration>[0-9]+)\s*(?P<units>[a-z]*)", re.IGNORECASE)
    
    MINUTE = 60
    HOUR   = 60 * MINUTE
    DAY    = 24 * HOUR
    WEEK   = 7 * DAY
    
    UNITS = {
             'w'       : WEEK,
             'week'    : WEEK,
             'd'       : DAY,
             'day'     : DAY,
             'h'       : HOUR,
             'hour'    : HOUR,
             'm'       : MINUTE,
             'min'     : MINUTE,
             'minute'  : MINUTE,
             's'       : 1
             }
    
    def to_python(self, value):
        Field.to_python(self, value)
        
        # Parse the duration
        m = DurationField.DURATION_RE.match(value)

        # Make sure the duration could be parsed
        if m is None:
            raise FieldValidationException("The value of '%s' for the '%s' parameter is not a valid duration" % (str(value), self.name))
        
        # Get the units and duration
        d = m.groupdict()
        
        units = d['units']
        
        # Parse the value provided
        try:
            duration = int(d['duration'])
        except ValueError:
            raise FieldValidationException("The duration '%s' for the '%s' parameter is not a valid number" % (d['duration'], self.name))
        
        # Make sure the units are valid
        if len(units) > 0 and units not in DurationField.UNITS:
            raise FieldValidationException("The unit '%s' for the '%s' parameter is not a valid unit of duration" % (units, self.name))
        
        # Convert the units to seconds
        if len(units) > 0:
            return duration * DurationField.UNITS[units]
        else:
            return duration

    def to_string(self, value):        
        return str(value)

class SelectorField(Field):
    """
    Represents a selector for getting information from a web-page. The selector is converted to a LXML CSS selector instance.
    """
    
    @classmethod
    def parse_selector(cls, value, name):
        try:
            return CSSSelector(value)
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
                ]
        
        ModularInput.__init__( self, scheme_args, args )
        
        if timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 30
    
    @staticmethod
    def get_file_path( checkpoint_dir, stanza ):
        """
        Get the path to the checkpoint file.
        
        Arguments:
        checkpoint_dir -- The directory where checkpoints ought to be saved
        stanza -- The stanza of the input being used
        """
        
        return os.path.join( checkpoint_dir, hashlib.md5(stanza).hexdigest() + ".json" )
        
    @classmethod
    def last_ran( cls, checkpoint_dir, stanza ):
        """
        Determines the date that the analysis was last performed for the given input (denoted by the stanza name).
        
        Arguments:
        checkpoint_dir -- The directory where checkpoints ought to be saved
        stanza -- The stanza of the input being used
        """
        
        fp = None
        
        try:
            fp = open( cls.get_file_path(checkpoint_dir, stanza) )
            checkpoint_dict = json.load(fp)
                
            return checkpoint_dict['last_run']
    
        finally:
            if fp is not None:
                fp.close()
        
    @classmethod
    def needs_another_run(cls, checkpoint_dir, stanza, interval, cur_time=None):
        """
        Determines if the given input (denoted by the stanza name) ought to be executed.
        
        Arguments:
        checkpoint_dir -- The directory where checkpoints ought to be saved
        stanza -- The stanza of the input being used
        interval -- The frequency that the analysis ought to be performed
        cur_time -- The current time (will be automatically determined if not provided)
        """
        
        try:
            last_ran = cls.last_ran(checkpoint_dir, stanza)
            
            return cls.is_expired(last_ran, interval, cur_time)
            
        except IOError as e:
            # The file likely doesn't exist
            return True
        
        except ValueError as e:
            # The file could not be loaded
            return True
        
        # Default return value
        return True
    
    @classmethod
    def save_checkpoint(cls, checkpoint_dir, stanza, last_run):
        """
        Save the checkpoint state.
        
        Arguments:
        checkpoint_dir -- The directory where checkpoints ought to be saved
        stanza -- The stanza of the input being used
        last_run -- The time when the analysis was last performed
        """
        
        fp = None
        
        try:
            fp = open( cls.get_file_path(checkpoint_dir, stanza), 'w' )
            
            d = { 'last_run' : last_run }
            
            json.dump(d, fp)
            
        except Exception:
            logger.exception("Failed to save checkpoint directory") 
            
        finally:
            if fp is not None:
                fp.close()
    
    @staticmethod
    def is_expired( last_run, interval, cur_time=None ):
        """
        Indicates if the last run time is expired based .
        
        Arguments:
        last_run -- The time that the analysis was last done
        interval -- The interval that the analysis ought to be done (as an integer)
        cur_time -- The current time (will be automatically determined if not provided)
        """
        
        if cur_time is None:
            cur_time = time.time()
        
        if (last_run + interval) < cur_time:
            return True
        else:
            return False
       
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
    def scrape_page(cls, url, selector, username=None, password=None, timeout=30, name_attributes=[], output_matches_as_mv=True, output_matches_as_separate_fields=False, charset_detect_meta_enabled=True, charset_detect_content_type_header_enabled=True, charset_detect_sniff_enabled=True, include_empty_matches=False):
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
        include_empty_matches -- Output matches that result in empty strings
        """
        
        if isinstance(url, basestring):
            url = URLField.parse_url(url, "url")
            
        if isinstance(selector, basestring):
            selector = SelectorField.parse_selector(selector, "selector")
        
        logger.debug('Running web input, url="%s"', url.geturl())
        
        try:
            # Get the HTML
                        
            # Make the HTTP object
            http = httplib2.Http(timeout=timeout, disable_ssl_certificate_validation=True)
            
            # Setup the credentials if necessary
            if username is not None or password is not None:
                
                if username is None:
                    username = ""
                    
                if password is None:
                    password = ""
                    
                http.add_credentials(username, password)
                
            # This will be where the result information will be stored
            result = {}
                        
            # Perform the request
            with Timer() as timer:
                response, content = http.request( url.geturl(), 'GET')
                
                # Get the hash of the content
                response_md5 = hashlib.md5(content).hexdigest()
                response_sha224 = hashlib.sha224(content).hexdigest()
                
                # Get the size of the content
                result['response_size'] = len(content)
            
            # Retrieve the meta-data
            result['response_code'] = response.status    
            result['request_time'] = timer.msecs
            
            # Determine the encoding
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
            
            # Store the encoding in the result
            result['encoding'] = encoding
            
            # Decode the content
            content = content.decode(encoding=encoding, errors='replace')
                
            # Parse the HTML
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
                        #print match
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
                                
                            # If the field doesn't exist
                            if output_matches_as_separate_fields:
                                result['match_' + field_name + "_" + str(fields_included)] = match_text
                        
                    if not field_made:
                        if output_matches_as_mv:
                            result['match'].append(match_text)
                        
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
    
    ##
    # 
    #
    # @param text The HTML (or XML) source text.
    # @return The plain text, as a Unicode string, if necessary.
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
    
    def run(self, stanza, cleaned_params, input_config):
        
        # Make the parameters
        interval        = cleaned_params["interval"]
        title           = cleaned_params["title"]
        url             = cleaned_params["url"]
        selector        = cleaned_params["selector"]
        username        = cleaned_params.get("username", None)
        password        = cleaned_params.get("password", None)
        name_attributes = cleaned_params.get("name_attributes", [])
        timeout         = self.timeout
        sourcetype      = cleaned_params.get("sourcetype", "web_input")
        index           = cleaned_params.get("index", "default")
        source          = stanza
        
        if self.needs_another_run( input_config.checkpoint_dir, stanza, interval ):
            
            """
            # Get the proxy configuration
            try:
                proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = self.get_proxy_config(input_config.session_key, conf_stanza)
            except splunk.ResourceNotFound:
                logger.error("The proxy configuration could not be loaded. The execution will be skipped for this input with stanza=%s", stanza)
                return
            """
            
            # Get the information from the page
            result = None
            
            try:
                result = WebInput.scrape_page(url, selector, username, password, timeout, name_attributes)
                
                matches = 0
                
                if 'match' in result:
                    matches = len(result['match'])
                
                logger.info("Successfully executed the website input, matches_count=%r, stanza=%s, url=%s", matches, stanza, url.geturl())
            except Exception:
                logger.exception("An exception occurred when attempting to retrieve information from the web-page") 
            
            # Process the result (f we got one)
            if result is not None:
                
                # Send the event
                self.output_event(result, stanza, index=index, source=source, sourcetype=sourcetype, unbroken=True, close=True)
            
                # Save the checkpoint so that we remember when we last 
                self.save_checkpoint(input_config.checkpoint_dir, stanza, int(time.time()) )
        
            
if __name__ == '__main__':
    try:
        web_input = WebInput()
        web_input.execute()
        sys.exit(0)
    except Exception:
        logger.exception("Unhandled exception was caught, this may be due to a defect in the script") # This logs general exceptions that would have been unhandled otherwise (such as coding errors)
        raise