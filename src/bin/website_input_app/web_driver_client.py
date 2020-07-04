"""
This implements the WebClient class for browsers that are controlled by Selenium WebDriver.

This includes the following classes:
  * WebDriverClient: base class of the web driver controlled clients
  * FireFoxClient: an instance of the client that loads content from Firefox
  * ChromeClient: an instance of the client that loads content from Google Chrome
"""

import os

try:
    from urlparse import urlunsplit, urlsplit
except ImportError:
    from urllib.parse import urlunsplit, urlsplit

import time
import platform
import sys
import urllib

from splunk.clilib.bundle_paths import make_splunkhome_path

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.common.exceptions import NoSuchElementException
from pyvirtualdisplay import Display
from easyprocess import EasyProcessCheckInstalledError
from website_input_app.web_client import WebClient, DEFAULT_USER_AGENT, LoginFormNotFound, FormAuthenticationFailed
from website_input_app.timer import Timer
from six.moves.urllib.parse import quote_plus
from six import text_type, binary_type

class WebDriverClient(WebClient):
    """
    A web-client based on Selenium that uses Firefox.
    """

    def __init__(self, timeout=30, user_agent=DEFAULT_USER_AGENT, logger=None):
        super(WebDriverClient, self).__init__(timeout, user_agent, logger)

        self.response = None
        self.driver = None
        self.display = None
        self.cookies = None

        self.add_browser_driver_to_path(logger)

    def get_response_headers(self):
        return {}

    @classmethod
    def add_browser_driver_to_path(cls, logger=None):

        driver_path = None

        if sys.platform == "linux2" or sys.platform == "linux":
            driver_path = "linux64"
        else:
            # Note that Windows will always return win32 (even on 64-bit hosts)
            # See http://bit.ly/2Dq6xM5
            driver_path = sys.platform

        full_driver_path = make_splunkhome_path(["etc", "apps", "website_input", "bin", "browser_drivers", driver_path])

        if not full_driver_path in os.environ["PATH"]:

            # Use the correct path separator per the platform
            # https://lukemurphey.net/issues/1782
            if os.name == 'nt':
                os.environ["PATH"] += ";" +full_driver_path
            else:
                os.environ["PATH"] += ":" +full_driver_path

            if logger:
                logger.debug("Updating path to include selenium driver path=%s, working_path=%s", full_driver_path, os.getcwd())

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
                split[1] = quote_plus(username) + ":" + quote_plus(password) + "@" + u.hostname
            else:
                split[1] = quote_plus(username) + ":" + quote_plus(password) + "@" + u.hostname + ":" + str(u.port)

            return urlunsplit(split)
        else:
            return url

    def get_content_from_driver(self, driver, url):

        # Load the page
        with Timer() as timer:

            # If we are already logged in (using form authentication), then don't update the URL
            if not self.is_logged_in:
                driver.get(self.add_auth_to_url(url, self.username, self.password))
            else:
                driver.get(url)

        self.response_time = timer.msecs

        # Wait for the content to load
        time.sleep(self.timeout)

        # Get the content
        content = driver.execute_script("return document.documentElement.outerHTML")
        return content

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
        client = None
        
        try:
            client = cls(10, DEFAULT_USER_AGENT)
            client.setProxy(proxy_type, proxy_server, proxy_port, proxy_user, proxy_pass)

            # Get the page
            client.get_url(login_url)

            # Get the forms
            form_elements = client.driver.find_elements_by_css_selector("form")

            # Go through each form and see if it has the elements
            for form_element in form_elements:
                password_element = None
                username_element = None

                for input_element in form_element.find_elements_by_css_selector("input"):

                    # See if this is the username field
                    if cls.is_field_for_username(input_element.get_attribute("name")) and input_element.get_attribute("type") in ["password", "text"]:
                        username_element = input_element

                    # See if this is the password field
                    if cls.is_field_for_password(input_element.get_attribute("name")) and input_element.get_attribute("type") in ["password", "text"]:
                        password_element = input_element

                # We found the elements!
                if password_element is not None and username_element is not None:
                    return form_element.get_attribute("name"), username_element.get_attribute("name"), password_element.get_attribute("name")

            return None, None, None
        finally:
            client.close()

    def doFormLogin(self, login_url, username_field=None, password_field=None, form_selector=""):

        # Detect the login form and fields if necessary
        username_field, password_field = self.getFormFieldsIfNecessary(login_url, username_field, password_field)
        
        if self.logger is not None:
            self.logger.debug("Detected username and password fields: %s, %s", username_field, password_field)

        self.cookies = None
        self.is_logged_in = False

        # Load the login form
        self.get_url(login_url, retain_driver=True, return_encoding=False)

        # Fill out the username and password
        try:
            username_field_element = self.driver.find_element_by_name(username_field)
            username_field_element.send_keys(self.username)
        except NoSuchElementException:
            raise FormAuthenticationFailed("Username field could not be found: " + username_field)

        try:
            password_field_element = self.driver.find_element_by_name(password_field)
            password_field_element.send_keys(self.password)
        except NoSuchElementException:
            raise FormAuthenticationFailed("Password field could not be found: " + password_field)

        # Find the form to submit
        try:
            form = self.driver.find_element_by_css_selector(form_selector + ' input[type="submit"], ' + form_selector + ' button[type="submit"]')
        except NoSuchElementException:
            raise FormAuthenticationFailed("Form field submit ould not be found for form")
        except Exception as exception:
            raise LoginFormNotFound(cause=exception)

        # Submit the form (or find_element_by_css_selector)
        if form is not None:
            form.click()
        else:
            raise LoginFormNotFound()

        # Get the cookies so that we can retain the logged in state
        self.cookies = self.driver.get_cookies()

        self.is_logged_in = True

    def get_driver(self):
        raise NotImplementedError("get_driver must be implemented in the inheriting class")

    def close(self):
        # Stop the driver so that the web-browser closes. Otherwise, the process would be left open.
        try:
            if self.driver is not None:
                self.driver.quit()
        finally:
            # Stop the display that is used to run a headless browser.
            if self.display is not None:
                self.display.stop()

            self.driver = None
            self.display = None

    def get_url(self, url, operation='GET', retain_driver=True, return_encoding=False):

        if not retain_driver:
            self.close()

        try:
            # Make an instance of the driver if necessary
            if not retain_driver or self.driver is None:
                self.display = self.get_display(self.logger)
                self.driver = self.get_driver()

            # Load the cookies if they are available
            if self.cookies is not None and len(self.cookies) > 0:
                for cookie in self.cookies:
                    self.driver.add_cookie(cookie)

            # Get the content
            content = self.get_content_from_driver(self.driver, url)

            # Decode the content
            if isinstance(content, binary_type):
                content_decoded, encoding = self.decode_content(content)
            else:
                encoding = None
                content_decoded = content

            # Return the results
            if return_encoding:
                return content_decoded, encoding
            else:
                return content_decoded

        finally:

            if not retain_driver:
                # Stop the driver so that the web-browser closes. Otherwise, the process would be left open.
                try:
                    if self.driver is not None:
                        self.driver.quit()
                        self.driver = None

                finally:
                    # Stop the display that is used to run a headless browser.
                    if self.display is not None:
                        self.display.stop()
                        self.display = None

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

        if self.user_agent is not None:
            profile.set_preference("general.useragent.override", self.user_agent)

        return profile

    def get_driver(self):
        profile = self.get_firefox_profile()

        # See https://lukemurphey.net/issues/2498
        options = Options()
        options.add_argument('-headless')

        if profile is not None:
            driver = webdriver.Firefox(profile, firefox_options=options, log_path=make_splunkhome_path(['var', 'log', 'splunk', 'geckodriver.log']))
        else:
            driver = webdriver.Firefox(firefox_options=options, log_path=make_splunkhome_path(['var', 'log', 'splunk', 'geckodriver.log']))

        return driver

class ChromeClient(WebDriverClient):
    DEFAULT_TO_HEADLESS = True

    def get_driver(self):
               
        chrome_options = webdriver.ChromeOptions()
        chrome_options_set = False

        # Use headless mode if requested
        if ChromeClient.DEFAULT_TO_HEADLESS:
            chrome_options.add_argument("--headless")
            chrome_options_set = True

        # Set the proxy configuration if necessary
        if self.proxy_type is not None and self.proxy_server is not None and self.proxy_port is not None:
            proxy = self.proxy_server + ":" + str(self.proxy_port)

            chrome_options.add_argument('--proxy-server=http://%s' % proxy)
            chrome_options_set = True

        # Set the user-agent as necessary
        if self.user_agent is not None:
            chrome_options.add_argument('--user-agent=%s' % self.user_agent)
            chrome_options_set = True

        # Set the Chrome options in web-driver
        if chrome_options_set and chrome_options:
            driver = webdriver.Chrome(chrome_options=chrome_options)
        else:
            driver = webdriver.Chrome()

        return driver
