"""
This class wraps various web-clients so that different ones can be used with the website inputs.

The classes included are:
  * Timer: a class for tracking the amount of time an operation takes
  * WebClient: a base class for web-clients (abstract, cannot be constructed)
  * Http2LibClient: a web-client based on httplib2
  * MechanizeClient: a web-client based on mechanize (supports form authentication)
"""

import re
import httplib2
from httplib2 import socks
import chardet
from six import binary_type, text_type

try:
    from urllib.request import (URLError)
except ImportError:
    from urllib2 import (URLError)

import socket
import mechanize

from website_input_app.timer import Timer

class WebClientException(Exception):
    def __init__(self, message=None, cause=None):
        if message is not None and cause is not None:
            super(WebClientException, self).__init__(message + u', caused by ' + repr(cause))
        self.cause = cause

class FormAuthenticationNotSupported(WebClientException):
    pass

class FormAuthenticationFailed(WebClientException):
    pass

class RequestTimeout(WebClientException):
    pass

class ConnectionFailure(WebClientException):
    pass

class LoginFormNotFound(FormAuthenticationFailed):
    pass

DEFAULT_USER_AGENT = 'Splunk Website Input (+https://splunkbase.splunk.com/app/1818/)'

class WebClient(object):
    """
    This is the base-class.
    """

    USERNAMES_LIST = ['username', 'email', 'email_address', 'user', 'username']
    PASSWORDS_LIST = ['password', 'pword', 'pass']

    DEFAULT_MAXIMUM_BYTES = 500 * 1024 # 500 KB

    def __init__(self, timeout=30, user_agent=DEFAULT_USER_AGENT, logger=None):

        # These are for storing the options for performing the request
        self.timeout = timeout
        self.headers = {}
        self.username = None
        self.password = None

        if user_agent is None:
            self.user_agent = DEFAULT_USER_AGENT
        else:
            self.user_agent = user_agent

        self.logger = logger

        # The proxy server information
        self.proxy_type = None
        self.proxy_server = None
        self.proxy_port = None
        self.proxy_user = None
        self.proxy_pass = None
        self.proxy_password = None

        # The following will be populated by the request
        self.response_code = None
        self.content = None
        self.response_time = None

        # Indicates if the browser is in a logged in state
        self.is_logged_in = False

        # Character set detection settings
        self.charset_detect_meta_enabled = True
        self.charset_detect_content_type_header_enabled = True
        self.charset_detect_sniff_enabled = True

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
            if isinstance(content, binary_type):
                find_meta_charset = re.compile(b"<meta(?!\s*(?:name|value)\s*=)[^>]*?charset\s*=[\s\"']*([^\s\"'/>]*)", re.IGNORECASE)
            else:
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
        if encoding is None and charset_detect_sniff_enabled and not isinstance(content, text_type):
            encoding_detection = chardet.detect(content)
            encoding = encoding_detection['encoding']

        # If all else fails, use the default
        if encoding is None:
            encoding = 'utf-8'

        # Make sure the encoding is a string so that it works on Python 3
        if isinstance(encoding, text_type):
            return encoding
        else:
            return encoding.decode('utf-8')

    def decode_content(self, content):
        # Detect the encoding
        encoding = WebClient.detect_encoding(content, self.get_response_headers(),
            charset_detect_content_type_header_enabled=self.charset_detect_content_type_header_enabled,
            charset_detect_meta_enabled=self.charset_detect_meta_enabled,
            charset_detect_sniff_enabled=self.charset_detect_sniff_enabled)

        # Decode the content
        try:
            if encoding is not None and encoding != "":
                content_decoded = content.decode(encoding=encoding, errors='replace')
            else:
                content_decoded = content
        except LookupError:
            # The charset was not recognized. Try to continue with what we have without decoding.
            # https://lukemurphey.net/issues/2190
            if self.logger is not None:
                self.logger.warn('Detected encoding was not recognized and the content will be evaluated (possibly with the wrong encoding), encoding_detected="%s"', encoding)
            
            content_decoded = content

        return content_decoded, encoding

    def normalize_response_headers(self, headers_dict):
        headers_normalized = {}

        for header in headers_dict.keys():
            headers_normalized[header.lower()] = headers_dict[header]

        return headers_normalized

    def add_header(self, header_name, header_value):
        self.headers[header_name] = header_value

    def setProxy(self, proxy_type, proxy_server, proxy_port, proxy_user, proxy_pass):
        self.proxy_type = proxy_type
        self.proxy_server = proxy_server
        self.proxy_port = proxy_port
        self.proxy_user = proxy_user
        self.proxy_pass = proxy_pass

    def setCredentials(self, username, password):
        self.username = username
        self.password = password

    @classmethod
    def detectFormFields(cls, login_url, proxy_type=None, proxy_server=None, proxy_port=None, proxy_user=None, proxy_pass=None, user_agent=DEFAULT_USER_AGENT):
        raise FormAuthenticationNotSupported()

    def getFormFieldsIfNecessary(self, login_url, username_field, password_field):
        """
        Get the username and password fields if necessary. If the fields are already provided
        (are not none), then those will be used. Otherwise, they will be auto-discovered.

        A FormAuthenticationFailed exception will be raised if either of the fields could not be
        associated with a value.
        """

        # Detect the login form and fields if necessary
        if username_field is None or password_field is None:
            _, username_field_name, password_field_name = self.detectFormFields(login_url, self.proxy_type, self.proxy_server, self.proxy_port, self.proxy_user, self.proxy_pass, self.user_agent)

            if username_field is None:
                username_field = username_field_name

            if password_field is None:
                password_field = password_field_name

        # Stop if some fields are missing
        if username_field is None:
            raise FormAuthenticationFailed("Username field is missing")

        if password_field is None:
            raise FormAuthenticationFailed("Password field is missing")

        return username_field, password_field

    def doFormLogin(self, login_url, username_field=None, password_field=None, form_selector=""):
        raise FormAuthenticationNotSupported()

    # The following need to be implemented by the inheriting classes
    def get_url(self, url, operation='GET', return_encoding=False):
        pass

    def get_response_headers(self):
        pass

    @classmethod
    def is_field_match(cls, field_name, in_list, not_in_list=None):
        if field_name is None:
            return False

        if in_list is None:
            return False

        field_name = field_name.lower()

        for name in in_list:
            if name in field_name and not cls.is_field_match(field_name, not_in_list):
                return True

        return False

    @classmethod
    def is_field_for_username(cls, field_name):
        return cls.is_field_match(field_name, cls.USERNAMES_LIST, cls.PASSWORDS_LIST)

    @classmethod
    def is_field_for_password(cls, field_name):
        return cls.is_field_match(field_name, cls.PASSWORDS_LIST)

    def close(self):
        pass

class Http2LibClient(WebClient):
    """
    A web-client based on http2lib.
    """

    def __init__(self, timeout=30, user_agent=DEFAULT_USER_AGENT, logger=None):
        super(Http2LibClient, self).__init__(timeout, user_agent, logger)

        # This is a reference to the HTTP client
        self.http = None
        self.response = None

        if user_agent is None:
            self.user_agent = DEFAULT_USER_AGENT
        else:
            self.user_agent = user_agent

    def resolve_proxy_type(self, proxy_type):

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
            if self.logger is not None:
                self.logger.warn("Proxy type is not recognized: %s", proxy_type)
            return None

    def get_http_client(self):

        if self.http is not None:
            return self.http

        else:
            # Determine which type of proxy is to be used (if any)
            resolved_proxy_type = self.resolve_proxy_type(self.proxy_type)
                
            # Setup the proxy info if so configured
            if resolved_proxy_type is not None and self.proxy_server is not None and len(self.proxy_server.strip()) > 0:
                proxy_info = httplib2.ProxyInfo(resolved_proxy_type, self.proxy_server, self.proxy_port, proxy_user=self.proxy_user, proxy_pass=self.proxy_password)

                if self.logger is not None:
                    self.logger.debug('Using a proxy server, type=%s, proxy_server="%s"', resolved_proxy_type, self.proxy_server)
            else:
                # No proxy is being used
                proxy_info = None

                if self.logger is not None:
                    self.logger.debug("Not using a proxy server")

            # Make the HTTP object
            self.http = httplib2.Http(proxy_info=proxy_info, timeout=self.timeout, disable_ssl_certificate_validation=True)

            # Setup the credentials if necessary
            if self.username is not None or self.password is not None:
                username, password = self.username, self.password

                if self.username is None:
                    username = ""

                if self.password is None:
                    password = ""

                self.http.add_credentials(username, password)

            return self.http

    def get_url(self, url, operation='GET', return_encoding=False):

        http = self.get_http_client()

        # Setup the headers as necessary
        if self.user_agent is not None:
            if self.logger is not None:
                self.logger.debug("Setting user-agent=%s", self.user_agent)

            self.headers['User-Agent'] = self.user_agent

        try:
            with Timer() as timer:
                self.response, self.content = http.request(url, 'GET', headers=self.headers)

            self.response_time = timer.msecs

        except socket.timeout:
            raise RequestTimeout()

        except socket.error as e:
            if e.errno in [60, 61]:
                raise RequestTimeout()
            raise ConnectionFailure()

        self.response_code = self.response.status

        # Decode the content
        content_decoded, encoding = self.decode_content(self.content)

        # Return the results
        if return_encoding:
            return content_decoded, encoding
        else:
            return content_decoded

    def get_response_headers(self):
        return self.normalize_response_headers(self.response)

class MechanizeClient(WebClient):
    """
    A web-client based on the mechanize browser. This client supports things such as form
    submission and authentication.
    """

    def __init__(self, timeout=30, user_agent=DEFAULT_USER_AGENT, logger=None):
        super(MechanizeClient, self).__init__(timeout, user_agent, logger)

        # This is a reference to the HTTP client
        self.http = None
        self.response = None
        self.response_headers = None

        self.browser = None
        self.is_logged_in = False

        if user_agent is None:
            self.user_agent = DEFAULT_USER_AGENT
        else:
            self.user_agent = user_agent

    @classmethod
    def get_browser(cls, proxy_type=None, proxy_server=None, proxy_port=None, proxy_user=None, proxy_pass=None):
        browser = mechanize.Browser()

        # Ignore robots.txt
        browser.set_handle_robots(False)

        # Ignore meta-refresh handlers
        browser.set_handle_refresh(False)

        # Setup the proxy
        if proxy_server is not None:
            proxy_str = ""

            # Add the user info
            if proxy_user is not None and proxy_pass is not None:
                proxy_str += proxy_user + ":" + proxy_pass.replace("@", "\@") + "@"

            # Add the proxy server
            proxy_str += proxy_server

            # Add the proxy server
            if proxy_port is not None:
                proxy_str += ":" + str(proxy_port)

            browser.set_proxies({"http": proxy_str, "https": proxy_str}) # e.g. joe:password@myproxy.example.com:3128

        return browser

    def get_url(self, url, operation='GET', return_encoding=False):

        # Get the browser
        if self.browser is None:
            self.browser = self.get_browser(self.proxy_type, self.proxy_server, self.proxy_port, self.proxy_user, self.proxy_pass)

        # Setup the credentials if necessary
        if self.username is not None or self.password is not None and not self.is_logged_in:
            username, password = self.username, self.password

            if username is None:
                username = ""

            if password is None:
                password = ""

            self.browser.add_password(url, self.username, self.password)

        # Set the user-agent
        if self.logger is not None:
            self.logger.debug("Setting user-agent=%s", self.user_agent)

        self.browser.addheaders = [('User-agent', self.user_agent)]

        try:
            with Timer() as timer:
                try:
                    self.response = self.browser.open(url, timeout=self.timeout)
                except mechanize.HTTPError:
                    # This excepts the HTTP error that can occur for authentication failures.
                    # We want to ignore the exception and keep moving so that the response can be
                    # examined.
                    # See http://bit.ly/2vrkCIq
                    pass

                content = self.response.read(self.DEFAULT_MAXIMUM_BYTES)

            self.response_time = timer.msecs

        except URLError as e:
            # Make sure the exception is a timeout
            if e.reason is not None and str(e.reason) == "timed out":
                raise RequestTimeout()
            else:
                raise ConnectionFailure(str(e), e)

        except Exception as e:
            raise ConnectionFailure(str(e), e)

        finally:
            if self.response is not None:
                self.response.close()

        # Get the response code
        self.response_code = self.response.code

        # Get the headers
        self.response_headers = {}
        res_info = self.response.info()

        for k in res_info.keys():
            self.response_headers[k] = res_info[k]

        # Decode the content
        content_decoded, encoding = self.decode_content(content)

        # Return the results
        if return_encoding:
            return content_decoded, encoding
        else:
            return content_decoded

    def get_response_headers(self):
        return self.normalize_response_headers(self.response_headers)

    @classmethod
    def detectFormFields(cls, login_url, proxy_type=None, proxy_server=None, proxy_port=None, proxy_user=None, proxy_pass=None, user_agent=DEFAULT_USER_AGENT):

        browser = cls.get_browser(proxy_type, proxy_server, proxy_port, proxy_user, proxy_pass)

        # Set the user-agent
        if user_agent is None:
            user_agent = DEFAULT_USER_AGENT

        browser.addheaders = [('User-agent', user_agent)]

        browser.open(login_url)

        # Check each form
        for form in browser.forms():
            password_control = None
            user_control = None

            # Try to find the controls
            for control in form.controls:

                # See if this is the password field
                if cls.is_field_for_password(control.name) and control.type in ["password", "text"]:
                    password_control = control

                # See if this is the username field
                if cls.is_field_for_username(control.name) and control.type in ["password", "text"]:
                    user_control = control

            if password_control is not None and user_control is not None:
                return form, user_control.name, password_control.name

        return None, None, None

    def doFormLogin(self, login_url, username_field=None, password_field=None, form_selector=""):
        try:

            self.browser = self.get_browser(self.proxy_type, self.proxy_server, self.proxy_port, self.proxy_user, self.proxy_pass)
            self.browser.addheaders = [('User-agent', self.user_agent)]
            self.browser.open(login_url)

            # Detect the login form and fields if necessary
            username_field, password_field = self.getFormFieldsIfNecessary(login_url, username_field, password_field)

            # Find the form with the username and password fields
            login_form = None

            for form in self.browser.forms():
                try:
                    form.find_control(username_field)
                    form.find_control(password_field)

                    login_form = form

                    break
                except mechanize._form_controls.ControlNotFoundError:
                    # This form didn't have the field, it doesn't appear to be the correct one
                    pass

            # Stop if we couldn't find the form
            if login_form is None:
                raise LoginFormNotFound("Login form was not found")

            # Set the form
            self.browser.form = login_form
            self.browser.form[username_field] = self.username
            self.browser.form[password_field] = self.password

            # Authenticate
            res = self.browser.submit()
            _ = res.read() # TODO: need?

            self.is_logged_in = True

        except Exception as e:
            raise FormAuthenticationFailed("Connection failed when loading the authentication form", e)

class DefaultWebClient(MechanizeClient):
    """
    This class represents the default web-client that is recommended.
    """
    pass
