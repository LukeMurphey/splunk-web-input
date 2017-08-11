"""
This controller provides some services that are important for the front-end to preview the output
from inputs. There are two main functions that this controller provides:

   scrape_page: this performs a page scrape like the input would. This is useful for previewing the
                output to make sure it looks like the expected output.
   load_page: this proxies an HTTP request so that the browser can circumvent the cross-domain
              protections that would otherwise not allow Javascript to be added to the page.
   test_browser: this checks to see if the given browser works
   
"""

import logging
import os
import sys
import lxml.html
from lxml.html.clean import Cleaner
import cherrypy
import urlparse
from httplib2 import ServerNotFoundError
import json

from splunk.appserver.mrsparkle.lib import jsonresponse
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from splunk.appserver.mrsparkle.lib.decorators import expose_page
import splunk.appserver.mrsparkle.controllers as controllers
import splunk
import splunk.util as util
import splunk.entity as entity
import splunk.rest as rest

sys.path.append(os.path.join("..", "..", "..", "bin"))
sys.path.append(make_splunkhome_path(["etc", "apps", "website_input", "bin"]))

from web_input import WebInput, WebScraper
from website_input_app.web_client import DefaultWebClient, MechanizeClient, LoginFormNotFound, FormAuthenticationFailed
from website_input_app.web_driver_client import FirefoxClient, ChromeClient
from website_input_app.modular_input import FieldValidationException, ModularInput
from cssselect import SelectorError, SelectorSyntaxError, ExpressionError

def setup_logger(level):
    """
    Setup a logger for the REST handler.
    """

    logger = logging.getLogger('splunk.appserver.web_input.controllers.WebInput')
    logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)

    file_handler = logging.handlers.RotatingFileHandler(make_splunkhome_path(['var', 'log', 'splunk', 'web_input_controller.log']), maxBytes=25000000, backupCount=5)

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

logger = setup_logger(logging.INFO)

class WebInputController(controllers.BaseController):
    '''
    Controller for previewing output of a web-input
    '''

    TEST_BROWSER_URL = "https://www.google.com"

    def render_error_json(self, msg):
        """
        Render an error such that it can be returned to the client as JSON.

        Arguments:
        msg -- A message describing the problem (a string)
        """

        output = jsonresponse.JsonResponse()
        output.data = []
        output.success = False
        output.addError(msg)
        return self.render_json(output)

    @staticmethod
    def hasCapability(capabilities, user=None, session_key=None):
        """
        Determine if the user has the given capabilities.
        """

        # Assign defaults if the user or session key is None
        if user is None:
            user = cherrypy.session['user']['name']

        if session_key is None:
            session_key = cherrypy.session.get('sessionKey')

        # Convert the capability to a list if it was a scalar
        if not isinstance(capabilities, list) or isinstance(capabilities, basestring):
            capabilities = [capabilities]

        # Get the capabilities that the user has
        try:
            users_capabilities = WebInputController.getCapabilities4User(user, session_key)
        except splunk.LicenseRestriction:
            # This can happen when the Splunk install is using the free license

            # Check to see if the Splunk install is using the free license and allow access if so
            # We are only going to check for this if it is the admin user since that is the user
            # that the non-authenticated user is logged in as when the free license is used.
            if user == 'admin':

                # See the free license is active
                response, content = rest.simpleRequest('/services/licenser/groups/Free?output_mode=json',
                                                       sessionKey=session_key)

                # If the response didn't return a 200 code, then the entry likely didn't exist and
                # the host is not using the free license
                if response.status == 200:

                    # Parse the JSON content
                    logger.warn(content)
                    license_info = json.loads(content)

                    if license_info['entry'][0]['content']['is_active'] == 1:
                        # This host is using the free license, allow this through
                        return True


        # Check the capabilities
        for capability in capabilities:
            if capability not in users_capabilities:
                return False

        return True

    @staticmethod
    def getCapabilities4User(user=None, session_key=None):
        """
        Get the capabilities for the given user.
        """

        roles = []
        capabilities = []

        # Get user info
        if user is not None:
            logger.info('Retrieving role(s) for current user: %s', user)
            userDict = entity.getEntities('authentication/users/%s' % (user), count=-1, sessionKey=session_key)

            for stanza, settings in userDict.items():
                if stanza == user:
                    for key, val in settings.items():
                        if key == 'roles':
                            logger.info('Successfully retrieved role(s) for user: %s', user)
                            roles = val

        # Get capabilities
        for role in roles:
            logger.info('Retrieving capabilities for current user: %s', user)
            roleDict = entity.getEntities('authorization/roles/%s' % (role), count=-1, sessionKey=session_key)

            for stanza, settings in roleDict.items():
                if stanza == role:
                    for key, val in settings.items():
                        if key == 'capabilities' or key == 'imported_capabilities':
                            logger.info('Successfully retrieved %s for user: %s', key, user)
                            capabilities.extend(val)

        return capabilities

    def render_error_html(self, msg):
        """
        Render a block of HTML for displaying an error.
        """

        return "<!DOCTYPE html><html>" \
                "<head>" \
                    '<style>body{' \
                    'font-family: Roboto, Droid, "Helvetica Neue", Helvetica, Arial, sans-serif;' \
                    'margin: 32px;' \
                    'font-size: 10pt;' \
                    '}</style>' \
                    '<title>Error</title>' \
                '</head>' \
                '<body>' + msg + '</body>' \
                '</html>'

    @expose_page(must_login=True, methods=['GET', 'POST'])
    def load_page(self, url, **kwargs):
        """
        Proxy a web-page through so that a UI can be displayed for showing potential results.
        """

        web_client = None

        try:

            # --------------------------------------
            # 1: Make sure that user has permission to make inputs. We don't want to allow people
            #    to use this as a general proxy.
            # --------------------------------------
            if not WebInputController.hasCapability('edit_modinput_web_input'):
                return self.render_error_html('You need the "edit_modinput_web_input" capability ' +
                                              'to make website inputs')

            # Don't allow proxying of the javascript files
            if url.endswith(".js"):
                cherrypy.response.headers['Content-Type'] = 'application/javascript'
                return ""

            # --------------------------------------
            # 2: Only allow HTTPS if the install is on Splunk Cloud
            # --------------------------------------
            if ModularInput.is_on_cloud(cherrypy.session.get('sessionKey')) and not url.startswith("https://"):
                return self.render_error_html('URLs on Splunk Cloud must use HTTPS protocol')

            # --------------------------------------
            # 3: Perform a request for the page
            # --------------------------------------

            # Get the proxy configuration
            conf_stanza = "default"

            try:
                web_input = WebInput(timeout=10)

                proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = \
                web_input.get_proxy_config(cherrypy.session.get('sessionKey'), conf_stanza)

            except splunk.ResourceNotFound:
                cherrypy.response.status = 202
                return self.render_error_html("Proxy server information could not be obtained")

            # Get the timeout to use
            timeout = None

            if 'timeout' in kwargs:
                try:
                    timeout = int(kwargs['timeout'])
                except ValueError:
                    timeout = 15
            else:
                timeout = 15

            # Get the user-agent
            user_agent = kwargs.get('user_agent', None)

            # Get the information on the browser to use
            browser = None

            if 'browser' in kwargs:
                browser = kwargs['browser']

            # Make the client
            if browser is None or browser == WebScraper.INTEGRATED_CLIENT:
                web_client = DefaultWebClient(timeout, user_agent, logger)
            elif browser == WebScraper.FIREFOX:
                web_client = FirefoxClient(timeout, user_agent, logger)
            elif browser == WebScraper.CHROME:
                web_client = ChromeClient(timeout, user_agent, logger)
            
            web_client.setProxy(proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)

            # Get the username and password
            username = kwargs.get('username', None)
            password = kwargs.get('password', None)

            username_field = kwargs.get('username_field', None)
            password_field = kwargs.get('password_field', None)
            authentication_url = kwargs.get('authentication_url', None)

            if username is not None and password is not None:
                username = kwargs['username']
                password = kwargs['password']

                username_field = kwargs.get('username_field', None)
                password_field = kwargs.get('password_field', None)
                authentication_url = kwargs.get('authentication_url', None)

                web_client.setCredentials(username, password)

                if authentication_url is not None:
                    logger.debug("Authenticating using form login in scrape_page")
                    web_client.doFormLogin(authentication_url, username_field, password_field)

            # Get the page
            try:
                content = web_client.get_url(url, 'GET')
                response = web_client.get_response_headers()
            except:
                logger.exception("Exception generated while attempting to content for url=%s", url)

                cherrypy.response.status = 500
                return self.render_error_html("Page preview could not be created using a web-browser")

            # --------------------------------------
            # 4: Render the content with the browser if necessary
            # --------------------------------------
            """
            if 'text/html' in response['content-type']:

                # Get the information on the browser to use
                browser = None

                if 'browser' in kwargs:
                    browser = kwargs['browser']

                # Try rendering the content using a web-browser
                try:
                    if browser is not None and browser != WebScraper.INTEGRATED_CLIENT:
                        
                        web_scraper = WebScraper(timeout=timeout)
                        web_scraper.set_proxy(proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)
                        web_scraper.set_authentication(username, password)
                        content = web_scraper.get_result_browser(urlparse.urlparse(url), browser)

                except:
                    logger.exception("Exception generated while attempting to get browser rendering or url=%s", url)

                    cherrypy.response.status = 500
                    return self.render_error_html("Page preview could not be created using a web-browser")
            """

            # --------------------------------------
            # 5: Rewrite the links in HTML files so that they also point to the internal proxy
            # --------------------------------------
            if "<html" in content:

                # Parse the content
                html = lxml.html.document_fromstring(content)

                # Rewrite the links to point to this internal proxy
                rewrite_using_internal_proxy = True

                if rewrite_using_internal_proxy:

                    def relocate_href(link):
                        """
                        Change the hrefs such that they go through the proxy.
                        """

                        link = urlparse.urljoin(url, link)

                        if link.endswith(".js"):
                            return ""
                        if not link.endswith(".css"):
                            return "load_page?url=" + link
                        else:
                            return link

                    html.rewrite_links(relocate_href)

                    # Block the href links
                    for element, attribute, _, _ in html.iterlinks():
                        if element.tag == "a" and attribute == "href":
                            element.set('href', "#")

                        elif element.tag == "form" and attribute == "action":
                            element.set('action', "?")
                else:
                    html.make_links_absolute(url)

                # Determine if we should clean the JS
                clean_script = True

                if 'clean_script' in kwargs:
                    clean_script = util.normalizeBoolean(kwargs['clean_script'])

                # Determine if we should clean the CSS
                clean_styles = False

                if 'clean_styles' in kwargs:
                    clean_styles = util.normalizeBoolean(kwargs['clean_styles'])

                # Clean up the HTML
                if clean_styles or clean_script:

                    kill_tags = []

                    if clean_script:
                        kill_tags = ["script"]

                    # Remove the script blocks
                    cleaner = Cleaner(page_structure=False, kill_tags=kill_tags, javascript=False,
                                      links=False, style=clean_styles, safe_attrs_only=False)

                    # Get the content
                    content = lxml.html.tostring(cleaner.clean_html(html))

                else:
                    content = lxml.html.tostring(html)

            # --------------------------------------
            # 6: Respond with the results
            # --------------------------------------
            if 'content-type' in response:
                cherrypy.response.headers['Content-Type'] = response['content-type']
            else:
                cherrypy.response.headers['Content-Type'] = 'text/html'

            # --------------------------------------
            # 7: Clear Javascript files
            # --------------------------------------
            if response.get('content-type', "") == "application/javascript" \
               or response.get('content-type', "") == "application/x-javascript" \
               or response.get('content-type', "") == "text/javascript" \
               or url.endswith(".js"):

                return ""

            return content

        except LoginFormNotFound:
            return self.render_error_html("Login form was not found")

        except FormAuthenticationFailed as e:
            return self.render_error_html("Form authentication failed: " + str(e))

        except:
            logger.exception("Error when attempting to proxy an HTTP request")
            cherrypy.response.status = 500
            return self.render_error_html("Page preview could not be created")

        finally:
            if web_client:
                web_client.close()

    @expose_page(must_login=True, methods=['GET']) 
    def test_browser(self, browser, **kwargs):
        """
        Determine if the given browser is configured and able to be used.
        """

        success = None

        web_scraper = WebScraper(3)

        # Set the proxy authentication
        try:
            web_input = WebInput(timeout=10)
            proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = web_input.get_proxy_config(cherrypy.session.get('sessionKey'), "default")

            web_scraper.set_proxy(proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)

        except splunk.ResourceNotFound:
            cherrypy.response.status = 202
            return self.render_error_json(_("Proxy server information could not be obtained"))

        try:
            result = web_scraper.scrape_page(selector="a", url=WebInputController.TEST_BROWSER_URL,
                                             browser=browser, include_raw_content=True)

            if not result:
                success = False
            elif len(result) < 1:
                success = False
            else:
                success = (result[0]['browser'] == browser)
        
        except Exception as exception:
            logger.exception("Exception generated when attempting to test the browser")
            success = False

        return self.render_json({
            'success' : success
        })

    @expose_page(must_login=True, methods=['GET'])
    def get_login_fields(self, url=None, **kwargs):

        web_input = WebInput(timeout=10)

        proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = \
        web_input.get_proxy_config(cherrypy.session.get('sessionKey'), "default")

        client = MechanizeClient(5)

        logger.debug("Using proxy %s to detect form fields", proxy_server)

        user_agent = kwargs.get('user_agent')

        _, username_field, password_field = client.detectFormFields(url, proxy_type, proxy_server, proxy_port, proxy_user, proxy_password, user_agent)

        return self.render_json({
            'username_field' : username_field or "",
            'password_field' : password_field or ""
        })

    @expose_page(must_login=True, methods=['GET', 'POST'])
    def scrape_page(self, **kwargs):
        """
        Perform a page scrape and return the results (useful for previewing a web_input modular
        input configuration)
        """

        result = [{}]

        # Run the input
        try:
            web_input = WebInput(timeout=10)

            kw = {}

            # Get the URL or URI
            url = None

            if 'url' in kwargs:
                url = kwargs['url']
            elif 'uri' in kwargs:
                url = kwargs['uri']

            if url is None:
                cherrypy.response.status = 202
                return self.render_error_json(_("No URL was provided"))

            # Get the selector
            selector = None

            if 'selector' in kwargs:
                selector = kwargs['selector']

            # Determine if we should include empty matches
            if 'empty_matches' in kwargs:
                kw['include_empty_matches'] = util.normalizeBoolean(kwargs['empty_matches'], True)

            # Get the use_element_name parameter
            if 'use_element_name' in kwargs:
                kw['use_element_name'] = util.normalizeBoolean(kwargs['use_element_name'], False)

            # Get the text_separator parameter
            if 'text_separator' in kwargs:
                kw['text_separator'] = kwargs['text_separator']

            # Get the output_as_mv parameter. This parameter is different from the name of the
            # argument that the class accepts and will be renamed accrdingly.
            if 'output_as_mv' in kwargs:
                kw['output_matches_as_mv'] = util.normalizeBoolean(kwargs['output_as_mv'], True)

                # If we are outputting as multi-valued parameters, then don't include the separate
                # fields
                if kw['output_matches_as_mv']:
                    kw['output_matches_as_separate_fields'] = False
                else:
                    # http://lukemurphey.net/issues/1643
                    kw['output_matches_as_separate_fields'] = True

            # Get the field match prefix
            if 'match_prefix' in kwargs:
                kw['match_prefix'] = kwargs['match_prefix']

            # Get the browser parameter
            if 'browser' in kwargs:
                kw['browser'] = kwargs['browser']

            # Get the page_limit parameter
            if 'page_limit' in kwargs:
                kw['page_limit'] = int(kwargs['page_limit'])

            # Get the depth_limit parameter
            if 'depth_limit' in kwargs:
                kw['depth_limit'] = int(kwargs['depth_limit'])

            # Get the depth_limit parameter
            if 'url_filter' in kwargs:
                kw['url_filter'] = kwargs['url_filter']

            # Get the name_attributes parameter
            if 'name_attributes' in kwargs:
                kw['name_attributes'] = kwargs['name_attributes']

            # Get the raw_content parameter
            if 'raw_content' in kwargs:
                kw['include_raw_content'] = util.normalizeBoolean(kwargs['raw_content'])

            # Only extract links using HTTPS if on Splunk Cloud
            if ModularInput.is_on_cloud(cherrypy.session.get('sessionKey')):
                kw['https_only'] = True

            # Otherwise, allow callers to specify which links to extract
            elif 'https_only' in kwargs:
                kw['https_only'] = util.normalizeBoolean(kwargs['https_only'])

            # Get the proxy configuration
            conf_stanza = "default"

            # Get the timeout parameter
            timeout = 5

            if 'timeout' in kwargs:
                try:
                    timeout = int(kwargs['timeout'])
                except:
                     # The timeout is invalid. Ignore this for now, it will get picked up when
                     # the user attempts to save the input
                    pass

            # Make the web scraper instance
            web_scraper = WebScraper(timeout)

            # Get the authentication information, if available
            username = None
            password = None

            if 'password' in kwargs and 'username' in kwargs:
                username = kwargs['username']
                password = kwargs['password']

                username_field = kwargs.get('username_field', None)
                password_field = kwargs.get('password_field', None)
                authentication_url = kwargs.get('authentication_url', None)

                if authentication_url is not None:
                    authentication_url = urlparse.urlparse(authentication_url)

                logger.debug("Using credentials for scrape_page")
                web_scraper.set_authentication(username, password, authentication_url, username_field, password_field)

            # Get the user-agent string
            if 'user_agent' in kwargs:
                web_scraper.user_agent = kwargs['user_agent']

            # Set the proxy authentication
            try:
                proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = web_input.get_proxy_config(cherrypy.session.get('sessionKey'), conf_stanza)

                web_scraper.set_proxy(proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)

            except splunk.ResourceNotFound:
                cherrypy.response.status = 202
                return self.render_error_json(_("Proxy server information could not be obtained"))

            # Scrape the page
            result = web_scraper.scrape_page(url, selector, **kw)

        except FieldValidationException as e:
            cherrypy.response.status = 220
            return self.render_error_json(_(str(e)))

        except ServerNotFoundError as e:
            cherrypy.response.status = 220
            return self.render_error_json(_(str(e)))

        except (SelectorError, SelectorSyntaxError, ExpressionError):
            cherrypy.response.status = 220
            return self.render_error_json(_("Selector is invalid. "))

        except LoginFormNotFound:
            cherrypy.response.status = 220
            return self.render_error_json("Login form was not found")

        except FormAuthenticationFailed:
            cherrypy.response.status = 220
            return self.render_error_json("Form authentication failed")

        except Exception as e:
            cherrypy.response.status = 500

            logger.exception("Error generated during execution")
            return self.render_error_json(_(str(e)))

        # Return the information
        if 'include_first_result_only' in kwargs:
            return self.render_json(result[0], set_mime='application/json')
        else:
            return self.render_json(result, set_mime='application/json')
