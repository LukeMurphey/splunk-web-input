"""
This controller provides some services that are important for the front-end to preview the output from inputs. There are two main functions that this controller provides:

   scrape_page: this performs a page scrape like the input would. This is useful for previewing the output to make sure it looks like the expected output.
   load_page: this proxies an HTTP request so that the browser can circumvent the cross-domain protections that would otherwise not allow Javascript to be added to the page.
   
"""

import logging
import os
import sys
import lxml.html
from lxml.html.clean import Cleaner
import cherrypy
import traceback
import urlparse

from splunk.appserver.mrsparkle.lib import jsonresponse
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
import splunk.appserver.mrsparkle.controllers as controllers

import splunk
import splunk.util as util
import splunk.entity as entity

sys.path.append( os.path.join("..", "..", "..", "bin") )
sys.path.append(make_splunkhome_path(["etc", "apps", "website_input", "bin"]))

from web_input import WebInput
from website_input_app.modular_input import FieldValidationException

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
    def getCapabilities4User(user=None, session_key=None):
        """
        Get the capabilities for the given user.
        """
        
        roles = []
        capabilities = []
        
        # Get user info              
        if user is not None:
            logger.info('Retrieving role(s) for current user: %s' % (user))
            userDict = entity.getEntities('authentication/users/%s' % (user), count=-1, sessionKey=session_key)
        
            for stanza, settings in userDict.items():
                if stanza == user:
                    for key, val in settings.items():
                        if key == 'roles':
                            logger.info('Successfully retrieved role(s) for user: %s' % (user))
                            roles = val
             
        # Get capabilities
        for role in roles:
            logger.info('Retrieving capabilities for current user: %s' % (user))
            roleDict = entity.getEntities('authorization/roles/%s' % (role), count=-1, sessionKey=session_key)
            
            for stanza, settings in roleDict.items():
                if stanza == role:
                    for key, val in settings.items():
                        if key == 'capabilities' or key =='imported_capabilities':
                            logger.info('Successfully retrieved %s for user: %s' % (key, user))
                            capabilities.extend(val)
            
        return capabilities     
    
    def render_error_html(self, msg):
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
        
        try:
                
            # --------------------------------------
            # 1: Make sure that user has permission to make inputs. We don't want to allow people to use this as a general proxy.
            # --------------------------------------
            
            # Get the user's name and session
            user = cherrypy.session['user']['name'] 
            session_key = cherrypy.session.get('sessionKey')
            capabilities = self.getCapabilities4User(user, session_key) 
            
            if 'edit_modinput_web_input' not in capabilities:
                return self.render_error_html("You need the 'edit_modinput_web_input' capability to make website inputs")
            
            # Don't allow proxying of the javascript files
            if url.endswith(".js"):
                cherrypy.response.headers['Content-Type'] = 'application/javascript'
                return ""
            
            # --------------------------------------
            # 2: Perform a request for the page
            # --------------------------------------
            
            # Get the proxy configuration
            conf_stanza = "default"
                
            try:
                web_input = WebInput(timeout=10)
                proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = web_input.get_proxy_config(cherrypy.session.get('sessionKey'), conf_stanza)
            except splunk.ResourceNotFound:
                cherrypy.response.status = 202
                return self.render_error_html("Proxy server information could not be obtained")
            
            # Get the username and password
            username = None
            password = None
            
            if 'username' in kwargs and 'password' in kwargs:
                username = kwargs['username']
                password = kwargs['password']
            
            http = WebInput.get_http_client(username, password, 30, proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)
            
            # Setup the headers as necessary
            user_agent = None
            headers = {}
                
            if user_agent is not None:
                logger.debug("Setting user-agent=%s", user_agent)
                headers['User-Agent'] = user_agent
            
            # Get the timeout to use
            timeout = None
            
            if 'timeout' in kwargs:
                try:
                    timeout = int(kwargs['timeout'])
                except ValueError:
                    timeout = 15
            else:
                timeout = 15
            
            # Get the page
            response, content = http.request(url, 'GET', headers=headers)
            
            # --------------------------------------
            # 3: Rewrite the links so that they also use the internal proxy
            # --------------------------------------
            if 'text/html' in response['content-type']:
                
                # Discover the encoding
                encoding = WebInput.detect_encoding(content, response)
                
                # Get the information on the browser to use
                browser = None
                
                if 'browser' in kwargs:
                    browser = kwargs['browser']
                
                # Try rendering the content using a web-browser
                try:
                    if browser is not None and browser != WebInput.INTEGRATED_CLIENT:
                        content = WebInput.get_result_browser(urlparse.urlparse(url), browser, timeout, username, password, proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)
                    
                    content_decoded = content.decode(encoding=encoding, errors='replace')
                except:
                    logger.exception("Exception generated while attempting to get browser rendering or url=%s", url)
                    
                    cherrypy.response.status = 500
                    return self.render_error_html("Page preview could not be created using a web-browser")
                
                # Parse the content
                html = lxml.html.document_fromstring(content_decoded)
                
                # Rewrite the links to point to this internal proxy
                rewrite_using_internal_proxy = True
                
                if rewrite_using_internal_proxy:
                    
                    def relocate_href(link):
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
                    cleaner = Cleaner(page_structure=False, kill_tags=kill_tags, javascript=False, links=False, style=clean_styles, safe_attrs_only=False)
                    
                    # Get the content
                    content = lxml.html.tostring(cleaner.clean_html(html))
                    
                else:
                    content = lxml.html.tostring(html)
            
            # --------------------------------------
            # 4: Respond with the results
            # --------------------------------------
            if 'content-type' in response:
                cherrypy.response.headers['Content-Type'] = response['content-type']
            else:
                cherrypy.response.headers['Content-Type'] = 'text/html'
                
            # --------------------------------------
            # 5: Clear Javascript files
            # --------------------------------------
            if response.get('content-type', "") == "application/javascript" or response.get('content-type', "") == "application/x-javascript" or response.get('content-type', "") == "text/javascript":
                return ""
            
            return content
        
        except:
            logger.exception("Error when attempting to proxy an HTTP request")
            cherrypy.response.status = 500
            #return self.render_error_json(_("Unable to proxy the request"))
            return self.render_error_html("Page preview could not be created")
    
    @expose_page(must_login=True, methods=['GET', 'POST']) 
    def scrape_page(self, **kwargs):
        """
        Perform a page scrape and return the results (useful for previewing a web_input modular input configuration)
        """
        
        result = [{}]
        
        # Run the input
        try:
            web_input = WebInput(timeout=10)
            
            kw = {}
            
            # Get the URL or URI
            url = None
            
            if( 'url' in kwargs):
                url = kwargs['url']
            elif( 'uri' in kwargs):
                url = kwargs['uri']
                
            if url is None:
                cherrypy.response.status = 202
                return self.render_error_json(_("No URL was provided"))
                
            # Get the selector
            selector = None
            
            if( 'selector' in kwargs):
                selector = kwargs['selector']
            
            # Get the authentication information, if available
            if( 'password' in kwargs and 'username' in kwargs):
                kw['username'] = kwargs['username']
                kw['password'] = kwargs['password']
                
            # Get the user-agent string
            if( 'user_agent' in kwargs):
                kw['user_agent'] = kwargs['user_agent']
            
            # Determine if we should include empty matches
            if 'include_empty_matches' in kwargs:
                kw['include_empty_matches'] = util.normalizeBoolean(kwargs['include_empty_matches'], True)
                
            # Get the use_element_name parameter
            if( 'use_element_name' in kwargs):
                kw['use_element_name'] = util.normalizeBoolean(kwargs['use_element_name'], False)
            
            # Get the text_separator parameter
            if( 'text_separator' in kwargs):
                kw['text_separator'] = kwargs['text_separator']
                
            # Get the output_as_mv parameter. This parameter is different from the name of the argument that the class accepts and will be renamed accrdingly.
            if( 'output_as_mv' in kwargs):
                kw['output_matches_as_mv'] = util.normalizeBoolean(kwargs['output_as_mv'], True)
                
                # If we are outputting as multi-valued parameters, then don't include the separate fields
                if(not kw['output_matches_as_mv']):
                    kw['output_matches_as_separate_fields'] = True
                
            # Get the timeout parameter
            kw['timeout'] = 5
            
            if( 'timeout' in kwargs):
                try:
                    kw['timeout'] = int(kwargs['timeout'])
                except:
                    pass # timeout is invalid. Ignore this for now, it will get picked up when the user attempts to save the input
                
            # Get the browser parameter
            if( 'browser' in kwargs):
                kw['browser'] = kwargs['browser']
                
            # Get the page_limit parameter
            if( 'page_limit' in kwargs):
                kw['page_limit'] = int(kwargs['page_limit'])
                
            # Get the depth_limit parameter
            if( 'depth_limit' in kwargs):
                kw['depth_limit'] = int(kwargs['depth_limit'])
                
            # Get the depth_limit parameter
            if( 'url_filter' in kwargs):
                kw['url_filter'] = kwargs['url_filter']
                
            # Get the name_attributes parameter
            if( 'name_attributes' in kwargs):
                kw['name_attributes'] = kwargs['name_attributes']
                
            # Get the user_agent parameter
            if( 'user_agent' in kwargs):
                kw['user_agent'] = kwargs['user_agent']

            # Get the raw_content parameter
            if( 'raw_content' in kwargs):
                kw['include_raw_content'] = util.normalizeBoolean(kwargs['raw_content'])
                
            # Get the text_separator parameter
            if( 'text_separator' in kwargs):
                kw['text_separator'] = kwargs['text_separator']
            
            # Get the proxy configuration
            conf_stanza = "default"
            
            try:
                proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = web_input.get_proxy_config(cherrypy.session.get('sessionKey'), conf_stanza)
                
                kw['proxy_type'] = proxy_type
                kw['proxy_server'] = proxy_server
                kw['proxy_port'] = proxy_port
                kw['proxy_user'] = proxy_user
                kw['proxy_password'] = proxy_password
                
            except splunk.ResourceNotFound:
                cherrypy.response.status = 202
                return self.render_error_json(_("Proxy server information could not be obtained"))
            
            # Scrape the page
            result = WebInput.scrape_page( url, selector, **kw)
            
            # Filter out results
            
        except FieldValidationException, e:
            cherrypy.response.status = 202
            return self.render_error_json(_(str(e)))
        
        except Exception, e:
            cherrypy.response.status = 500
            #logger.exception(e)
            logger.error("Error generated during execution: " + traceback.format_exc() )
            return self.render_error_json(_("The request could not be completed: " + traceback.format_exc()))
        
        # Return the information
        if 'include_first_result_only' in kwargs:
            return self.render_json(result[0], set_mime='application/json')
        else:
            return self.render_json(result, set_mime='application/json')
