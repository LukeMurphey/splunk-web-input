"""
This class wraps various web-clients so that different ones can be used.
"""
import urllib2
import httplib2
from httplib2 import socks
import socket
import mechanize

class FormAuthenticationNotSupported(Exception):
    pass

class RequestTimeout(Exception):
    pass

class ConnectionFailure(Exception):
    pass

class WebClient(object):
    """
    This is the base-class.
    """

    def __init__(self, timeout=30, user_agent=None, logger=None):

        # These are for storing the options for performing the request
        self.timeout = timeout
        self.user_agent = user_agent
        self.headers = {}
        self.username = None
        self.password = None

        self.logger = logger

        # The proxy server information
        self.proxy_type = None
        self.proxy_server = None
        self.proxy_port = None
        self.proxy_user = None
        self.proxy_pass = None

        # The following will be populated by the request
        self.response_code = None
        self.content = None

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

    # The following need to be implemented by the inheriting classes
    def get_url(self, url, operation='GET'):
        pass

    def get_response_headers(self):
        pass

class Http2LibClient(WebClient):
    """
    A web-client based on http2lib.
    """

    def __init__(self, timeout=30, user_agent=None, logger=None):
        super(Http2LibClient, self).__init__(timeout, user_agent, logger)

        # This is a reference to the HTTP client
        self.http = None
        self.response = None

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

    def get_url(self, url, operation='GET'):

        http = self.get_http_client()

        # Setup the headers as necessary
        if self.user_agent is not None:
            if self.logger is not None:
                self.logger.debug("Setting user-agent=%s", self.user_agent)

            self.headers['User-Agent'] = self.user_agent

        try:
            self.response, self.content = http.request(url, 'GET', headers=self.headers)
        except socket.timeout:
            raise RequestTimeout()

        except socket.error as e:
            if e.errno in [60, 61]:
                raise RequestTimeout()
            raise ConnectionFailure()

        self.response_code = self.response.status

        return self.content

    def get_response_headers(self):
        return self.response

class MechanizeClient(WebClient):
    """
    A web-client based on the mechanize browser.
    """

    def __init__(self, timeout=30, user_agent=None, logger=None):
        super(MechanizeClient, self).__init__(timeout, user_agent, logger)

        # This is a reference to the HTTP client
        self.http = None
        self.response = None
        self.response_headers = None

    def get_url(self, url, operation='GET'):

        browser = mechanize.Browser()

        # Ignore robots.txt
        browser.set_handle_robots(False)

        # Setup the credentials if necessary
        if self.username is not None or self.password is not None:
            username, password = self.username, self.password

            if self.username is None:
                username = ""

            if self.password is None:
                password = ""

            browser.add_password(url, self.username, self.password)

        # Set the user-agent
        if self.logger is not None:
            self.logger.debug("Setting user-agent=%s", self.user_agent)

        browser.addheaders = [('User-agent', self.user_agent)]

        try:
            self.response = browser.open(url, timeout=self.timeout)
            content = self.response.read()
        except mechanize.HTTPError as e:
            print dir(e)
            print e
            pass
        except urllib2.URLError as e:
            # Make sure the exception is a timeout
            if e.reason is not None and str(e.reason) == "timed out":
                raise RequestTimeout()
            else:
                raise e

        # Get the response code
        self.response_code = self.response.code

        # Get the headers
        self.response_headers = {}
        res_info = self.response.info()

        for k in res_info.keys():
            self.response_headers[k] = res_info[k]

        return content

    def get_response_headers(self):
        return self.response_headers