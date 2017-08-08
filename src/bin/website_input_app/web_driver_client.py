"""
This implements the WebClient class for browsers that are controlled by Selenium WebDriver.

This includes the following classes:

  * WebDriverClient: base class fo the web driver controlled clients
  * FireFoxClient: an instance of the client that loads content from Firefox
  * ChromeClient: an instance of the client that loads content from Google Chrome
"""

import os
from urlparse import urlparse, urljoin, urlunsplit, urlsplit
import time

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path, get_apps_dir

from web_client import WebClient, DEFAULT_USER_AGENT
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from pyvirtualdisplay import Display
from easyprocess import EasyProcessCheckInstalledError

class WebDriverClient(WebClient):
    """
    A web-client based on Selenium that uses Firefox.
    """

    def __init__(self, timeout=30, user_agent=DEFAULT_USER_AGENT, logger=None):
        super(WebDriverClient, self).__init__(timeout, user_agent, logger)

        self.response = None

    def get_response_headers(self):
        return {}

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
        else:
            return url

    def get_content_from_driver(self, driver, url):

        # Load the page
        driver.get(self.add_auth_to_url(url, self.username, self.password))

        # Wait for the content to load
        time.sleep(self.timeout)

        # Get the content
        return driver.execute_script("return document.documentElement.outerHTML")

    @classmethod
    def get_display(cls, logger=None):

        # Start a display so that this works on headless hosts
        if not os.name == 'nt':
            try:
                display = Display(visible=0, size=(800, 600))
                display.start()

                return display
            except EasyProcessCheckInstalledError:
                if logger:
                    logger.warn("Failed to load the virtual display; the web-browser might not be able to run if this is a headless host")
            except Exception:
                if logger:
                    logger.exception("Failed to load the virtual display; the web-browser might not be able to run if this is a headless host")

    @classmethod
    def detectFormFields(cls, login_url, proxy_type=None, proxy_server=None, proxy_port=None, proxy_user=None, proxy_pass=None, user_agent=DEFAULT_USER_AGENT):
        pass

    def doFormLogin(self, login_url, username_field=None, password_field=None):
        pass

    def get_driver(self):
        raise NotImplementedError("get_driver must be implemented in the inheriting class")

    def get_url(self, url, operation='GET'):
    
        display = None
        driver = None

        try:
            display = self.get_display(self.logger)

            driver = self.get_driver()

            return self.get_content_from_driver(driver, url)

        finally:

            # Stop the driver so that the web-browser closes. Otherwise, the process would be left open.
            try:
                if driver is not None:
                    driver.quit()
            finally:
                # Stop the display that is used to run a headless browser.
                if display is not None:
                    display.stop()

class FirefoxClient(WebDriverClient):
    """
    A web-client based on Selenium that uses Firefox .
    """

    def get_firefox_profile(self):
        profile = webdriver.FirefoxProfile()

        # This is necessary in order to avoid the dialog that FireFox uses to stop potential
        # phishing attacks that use credentials encoded in the URL
        # See http://lukemurphey.net/issues/1658
        profile.set_preference('network.http.phishy-userpass-length', 255)

        # Return none if no proxy is defined
        if self.proxy_server is None or self.proxy_port is None:
            pass

            if self.logger is not None:
                self.logger.debug("No proxy defined for Firefox")

        # Use a socks proxy
        elif self.proxy_type == "socks4" or self.proxy_type == "socks5":
            profile.set_preference('network.proxy.type', 1)
            profile.set_preference('network.proxy.socks', self.proxy_server)
            profile.set_preference('network.proxy.socks_port', int(self.proxy_port))

            if self.logger is not None:
                self.logger.debug("Using a proxy with Firefox, type=", self.proxy_type)

        # Use an HTTP proxy
        elif self.proxy_type == "http":

            profile.set_preference('network.proxy.type', 1)
            profile.set_preference('network.proxy.http', self.proxy_server)
            profile.set_preference('network.proxy.http_port', int(self.proxy_port))
            profile.set_preference('network.proxy.ssl', self.proxy_server)
            profile.set_preference('network.proxy.ssl_port', int(self.proxy_port))

            if self.logger is not None:
                self.logger.debug("Using a proxy with Firefox, type=", self.proxy_type)
                
        return profile

    def get_driver(self):
        profile = self.get_firefox_profile()

        if profile is not None:
            driver = webdriver.Firefox(profile, log_path=make_splunkhome_path(['var', 'log', 'splunk', 'geckodriver.log']))
        else:
            driver = webdriver.Firefox(log_path=make_splunkhome_path(['var', 'log', 'splunk', 'geckodriver.log']))

        return driver

class ChromeClient(WebDriverClient):

    def get_driver(self):
               
        chrome_options = None

        # Get the proxy configuration if necessary
        if self.proxy_type is not None and self.proxy_server is not None and self.proxy_port is not None:
            proxy = self.proxy_server + ":" + str(self.proxy_port)

            chrome_options = webdriver.ChromeOptions()
            chrome_options.add_argument('--proxy-server=http://%s' % proxy)

        if chrome_options:
            driver = webdriver.Chrome(chrome_options=chrome_options)
        else:
            driver = webdriver.Chrome()

        return driver