import logging
import os
import sys
import lxml.html
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

from web_input import URLField, SelectorField, WebInput
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
    
    @expose_page(must_login=True, methods=['GET']) 
    def load_page(self, url, **kwargs):
        """
        Proxy a web-page through so that a UI can be displayed for showing potential results.
        """
        
        try:
                
            # --------------------------------------
            # 1: Make sure that user has permission to make inputs. We don't want to allow people to use this as a general proxy.
            # --------------------------------------
            
            #edit_modinput_web_input
            
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
                return self.render_error_json(_("Proxy server information could not be obtained"))
            
            http = WebInput.get_http_client(None, None, 30, proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)
            
            # Setup the headers as necessary
            user_agent = None
            headers = {}
                
            if user_agent is not None:
                logger.info("Setting user-agent=%s", user_agent)
                headers['User-Agent'] = user_agent
            
            # Get the page
            response, content = http.request(url, 'GET', headers=headers)
            
            # --------------------------------------
            # 3: Rewrite the links so that they also use the 
            # --------------------------------------
            
            if 'text/html' in response['content-type']:
                
                # Discover the encoding
                encoding = WebInput.detect_encoding(content, response)
                content_decoded = content.decode(encoding=encoding, errors='replace')
                
                # Parse the content
                html = lxml.html.document_fromstring(content_decoded)
                
                rewrite_using_internal_proxy = True
                
                if rewrite_using_internal_proxy:
                    def relocate_href(link):
                        link = urlparse.urljoin(url, link)
                        if not link.endswith(".css") and not link.endswith(".js"):
                            return "/custom/website_input/web_input_controller/load_page?url=" + link #TODO replace with something that supports custom root endpoints
                        else:
                            return link
                    html.rewrite_links(relocate_href)
                    #html.make_links_absolute("/custom/website_input/web_input_controller/load_page?url=")
                else:
                    html.make_links_absolute(url)
                
                content = lxml.html.tostring(html)
            
            # --------------------------------------
            # 4: Respond with the results
            # --------------------------------------
            if 'content-type' in response:
                cherrypy.response.headers['Content-Type'] = response['content-type']
            else:
                cherrypy.response.headers['Content-Type'] = 'text/html'
                
            return content
        
        except:
            logger.exception("Error when attempting to proxy an HTTP request")
            cherrypy.response.status = 500
            return self.render_error_json(_("Unable to proxy the request"))
    
    @expose_page(must_login=True, methods=['GET', 'POST']) 
    def scrape_page(self, url, selector, **kwargs):
        """
        Perform a page scrape and return the results (useful for previewing a web_input modular input configuration)
        """
        
        result = [{}]
        
        # Run the input
        try:
            web_input = WebInput(timeout=10)
            
            # Get the authentication information, if available
            username = None
            password = None
            
            if( 'password' in kwargs and 'username' in kwargs):
                username = kwargs['username']
                password = kwargs['password']
                
            # Get the user-agent string
            user_agent = None
            
            if( 'user_agent' in kwargs):
                user_agent = kwargs['user_agent']
            
            # Determine if we should include empty matches
            include_empty_matches = False
            
            if 'include_empty_matches' in kwargs:
                include_empty_matches = util.normalizeBoolean(kwargs['include_empty_matches'], True)
                
            # Get the use_element_name parameter
            """
            use_element_name = None
            
            if( 'use_element_name' in kwargs):
                use_element_name = util.normalizeBoolean(kwargs['use_element_name'], False)
            """
            use_element_name = False
            
            # Get the text_separator parameter
            text_separator = " "
            
            if( 'text_separator' in kwargs):
                text_separator = kwargs['text_separator']
                
            # Get the timeout parameter
            timeout = 5
            
            if( 'timeout' in kwargs):
                try:
                    timeout = int(kwargs['timeout'])
                except:
                    pass # timeout is invalid. Ignore this for now, it will get picked up when the user attempts to save the input
                
            # Get the browser parameter
            browser = " "
            
            if( 'browser' in kwargs):
                browser = kwargs['browser']
            
            # Get the proxy configuration
            conf_stanza = "default"
            
            try:
                proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = web_input.get_proxy_config(cherrypy.session.get('sessionKey'), conf_stanza)
            except splunk.ResourceNotFound:
                cherrypy.response.status = 202
                return self.render_error_json(_("Proxy server information could not be obtained"))
            
            # Scrape the page
            result = WebInput.scrape_page( url, selector, username=username, password=password, include_empty_matches=include_empty_matches, proxy_type=proxy_type, proxy_server=proxy_server, proxy_port=proxy_port, proxy_user=proxy_user, proxy_password=proxy_password, user_agent=user_agent, use_element_name=use_element_name, text_separator=text_separator, browser=browser, timeout=timeout)
            
        except FieldValidationException, e:
            cherrypy.response.status = 202
            return self.render_error_json(_(str(e)))
        
        except Exception, e:
            cherrypy.response.status = 500
            #logger.exception(e)
            logger.error("Error generated during execution: " + traceback.format_exc() )
            return self.render_error_json(_("The request could not be completed: " + traceback.format_exc()))
        
        # Return the information
        return self.render_json(result[0])
