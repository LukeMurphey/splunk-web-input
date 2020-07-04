"""
This module provides the classes for support web-scraping in Splunk.

The classes included are:

  * DiscoveredURL: represents a URL that was discovered
  * WebScraper: a class for performing web-scrapes
"""

import re
import os
import sys

from six.moves.urllib.parse import urlparse, urljoin

import hashlib
import lxml.html
from lxml.etree import XMLSyntaxError
import httplib2
from collections import OrderedDict

from website_input_app.web_client import DefaultWebClient, RequestTimeout, ConnectionFailure, LoginFormNotFound, FormAuthenticationFailed, WebClientException
from website_input_app.web_driver_client import FirefoxClient, ChromeClient
from website_input_app.selector_field import SelectorField
from six import binary_type, text_type, string_types

path_to_mod_input_lib = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modular_input.zip')
sys.path.insert(0, path_to_mod_input_lib)
from modular_input import  URLField

class DiscoveredURL(object):
    """
    This class represents a discovered URL so that we can keep a list of URLs to scan when
    spidering.
    """

    depth = None
    processed = False

    def __init__(self, depth, processed=False):
        self.depth = depth
        self.processed = False

class WebScraper(object):
    """
    This class performs the operation of web-scraping.
    """

    BROWSER_FIELD = 'browser'
    RESPONSE_SIZE_FIELD = 'response_size'
    RESPONSE_CODE_FIELD = 'response_code'
    REQUEST_TIME_FIELD = 'request_time'
    URL_FIELD = 'url'
    CONTENT_MD5_FIELD = 'content_md5'
    CONTENT_SHA224_FIELD = 'content_sha224'
    ENCODING_FIELD = 'encoding'
    RAW_MATCH_COUNT_FIELD = 'raw_match_count'
    CONTENT_FIELD = 'content'
    TIMED_OUT_FIELD = 'timed_out'
    TITLE_FIELD = 'title'
    TIME_FIELD = '_time'

    RESERVED_FIELD_NAMES = [
        # Splunk reserved fields:
        'source',
        'sourcetype',
        'host',
        '_time',
        'punct',

        # Internal reserved fields:
        REQUEST_TIME_FIELD,
        RESPONSE_CODE_FIELD,
        RAW_MATCH_COUNT_FIELD
    ]

    FIREFOX = "firefox"
    INTEGRATED_CLIENT = "integrated_client"
    SAFARI = "safari"
    INTERNET_EXPLORER = "internet_explorer"
    CHROME = "chrome"

    SUPPORTED_BROWSERS = [INTEGRATED_CLIENT, FIREFOX, CHROME]

    # This is a list of the fields that this class will put into the result object that are not the raw data that is
    # being extracted.
    GENERATED_FIELDS = [BROWSER_FIELD, RESPONSE_SIZE_FIELD, RESPONSE_CODE_FIELD, REQUEST_TIME_FIELD, URL_FIELD,
                        CONTENT_MD5_FIELD, CONTENT_SHA224_FIELD, ENCODING_FIELD, RAW_MATCH_COUNT_FIELD, CONTENT_FIELD,
                        TIMED_OUT_FIELD, TITLE_FIELD, TIME_FIELD]

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

    def __init__(self, timeout=30, logger=None):
        self.timeout = timeout
        self.logger = logger

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
        charset_detect_meta_enabled -- Detect via the meta tag
        charset_detect_content_type_header_enabled -- Detect the content-type header
        charset_detect_sniff_enabled -- Detect by looking at the content
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

            if self.logger is not None:
                self.logger.info('Performing web-scrape, url="%s"', url.geturl())

            if match_prefix is None:
                match_prefix = ''

            # This will be where the result information will be stored
            result = OrderedDict()

            if additional_fields is not None:
                for k, v in additional_fields.items():
                    result[k] = v

            # Perform the request
            web_client.set_charset_detection(self.charset_detect_meta_enabled, self.charset_detect_content_type_header_enabled, self.charset_detect_sniff_enabled)
            content, encoding = web_client.get_url(url.geturl(), return_encoding=True)
            result[WebScraper.ENCODING_FIELD] = encoding

            # Assign the browser string to the integrated client
            if browser is None or browser == "":
                browser = WebScraper.INTEGRATED_CLIENT
            
            result[WebScraper.BROWSER_FIELD] = browser

            # Get the size of the content
            result[WebScraper.RESPONSE_SIZE_FIELD] = len(content)

            # Retrieve the meta-data
            if web_client.response_code is not None:
                result[WebScraper.RESPONSE_CODE_FIELD] = web_client.response_code

            result[WebScraper.URL_FIELD] = url.geturl()
            result[WebScraper.REQUEST_TIME_FIELD] = web_client.response_time

            # Get the hash of the content
            if content is not None:
                if encoding is None:
                    encoding = 'utf-8'

                content_bytes = content.encode(encoding, "replace")
                result[WebScraper.CONTENT_MD5_FIELD] = hashlib.md5(content_bytes).hexdigest()
                result[WebScraper.CONTENT_SHA224_FIELD] = hashlib.sha224(content_bytes).hexdigest()

            # By default, assume we couldn't parse the content
            tree = None

            # Parse the HTML
            try:
                tree = lxml.html.fromstring(content)
            except (ValueError, XMLSyntaxError):
                # lxml will refuse to parse a Unicode string containing XML that declares the encoding even if the encoding declaration matches the encoding used.
                # This is odd since this exception will be thrown even though the app successfully determined the encoding (it matches the declaration in the XML).
                # The app handles this by attempting to parse the content a second time if it failed when using Unicode. This is necessary because I cannot allow
                # lxml to discover the encoding on its own since it doesn't know what the HTTP headers are and cannot sniff the encoding as well as the input does
                # (which uses several methods to determine the encoding).
                if self.logger is not None:
                    self.logger.info('The content is going to be parsed without decoding because the parser refused to parse it with the detected encoding (http://goo.gl/4GRjJF), url="%s", encoding="%s"', url.geturl(), encoding)

                try:
                    tree = lxml.html.fromstring(content)
                except Exception:
                    if self.logger is not None:
                        self.logger.info('The content could not be parsed, it doesn\'t appear to be valid HTML, url="%s"', url.geturl())

            except Exception:
                if self.logger is not None:
                    self.logger.info('An exception was generated while attempting to parse the content, url="%s"', url.geturl())

            # Perform extraction if a selector is provided
            if selector is not None and tree is not None:

                # Apply the selector to the DOM tree
                matches = selector(tree)

                # Store the raw match count (the nodes that the CSS matches)
                result[WebScraper.RAW_MATCH_COUNT_FIELD] = len(matches)
  
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
                result[WebScraper.CONTENT_FIELD] = content

            # If we are to extract links, do it
            if tree is not None:
                if extracted_links is not None and source_url_depth is not None:

                    for extracted in self.extract_links(tree, url.geturl(), url_filter=url_filter, https_only=https_only):

                        # Add the extracted link if it is not already in the list
                        if extracted not in extracted_links:

                            # Add the discovered URL (with the appropriate depth)
                            extracted_links[extracted] = DiscoveredURL(source_url_depth + 1)
                else:
                    if self.logger is not None:
                        self.logger.debug("Not extracting links since extracted_links is None")

        # Handle time outs    
        except RequestTimeout:

            # Note that the connection timed out    
            result[WebScraper.TIMED_OUT_FIELD] = True

        except ConnectionFailure:
            result[WebScraper.TIMED_OUT_FIELD] = True

            """
            except httplib2.SSLHandshakeError as e:
                if self.logger is not None:
                    self.logger.warn('Unable to connect to website due to an issue with the SSL handshake, url="%s", message="%s"', url.geturl(), str(e))
                return None # Unable to connect to this site due to an SSL issue
            """
        except httplib2.RelativeURIError:
            if self.logger is not None:
                self.logger.debug('Ignoring relative URI, url="%s", message="%s"', url.geturl(), str(e))
            return None # Not a real URI

        except Exception:
            if self.logger is not None:
                self.logger.exception("A general exception was thrown when executing a web request")
            raise

        return result

    def scrape_page(self, url, selector, name_attributes=[], output_matches_as_mv=True,
                    output_matches_as_separate_fields=False, include_empty_matches=False,
                    use_element_name=False, page_limit=1, depth_limit=50, url_filter=None,
                    include_raw_content=False, text_separator=None, browser=None,
                    additional_fields=None, match_prefix=None, empty_value='NULL',
                    https_only=False, output_fx=None):
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
        output_fx -- Run this function against the results for outputting them
        """

        if isinstance(url, string_types):
            url = URLField.parse_url(url, "url")

        if isinstance(selector, string_types):
            selector = SelectorField.parse_selector(selector, "selector")

        if self.logger is not None:
            self.logger.info('Running web input, url="%s"', url.geturl())

        results = []
        results_count = 0

        client = None

        try:

            # Make the browser client if necessary
            if browser == WebScraper.FIREFOX:
                client = FirefoxClient(timeout=self.timeout, user_agent=self.user_agent, logger=self.logger)
            elif browser == WebScraper.CHROME:
                client = ChromeClient(timeout=self.timeout, user_agent=self.user_agent, logger=self.logger)
            else:
                client = DefaultWebClient(self.timeout, user_agent=self.user_agent, logger=self.logger)

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

            #if self.logger is not None:
            #    self.logger.info('Running web input, url="%s"', url.geturl())

            # Process each result
            while results_count < page_limit:

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
                    if self.logger is not None:
                        self.logger.debug("No more URLs in the list to process")
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
                    if output_fx is None:
                        results.append(result)
                        results_count = len(results)
                    else:
                        output_fx(result)
                        results_count = results_count + 1

        except (LoginFormNotFound, FormAuthenticationFailed, WebClientException) as e:
            raise e

        except Exception:
            # TODO: remove this one or the one in get_result_single()
            if self.logger is not None:
                self.logger.exception("A general exception was thrown when executing a web request")
            raise

        finally:
            if client:
                client.close()

        # Return the results if we didn't use the output function 
        if output_fx is None:
            return results

        # Otherwise the results count
        else:
            return results_count
    
    @classmethod
    def unescape(cls, text):
        """
        Removes HTML or XML character references and entities from a text string. Return the plain text, as a Unicode string, if necessary.
        
        Argument:
        text -- The HTML (or XML) source text.
        """

        if text is None:
            return None

        try:
            # Python 2.6-2.7 
            from HTMLParser import HTMLParser
            h = HTMLParser()
            return h.unescape(text)
        except ImportError:
            # Python 3
            import html
            return html.unescape(text)

            