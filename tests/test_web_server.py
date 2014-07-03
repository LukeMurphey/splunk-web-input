import SimpleHTTPServer
import SocketServer
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import os
import base64

class Handler(BaseHTTPRequestHandler):
    ''' Main class to present webpages and authentication. '''
    def do_HEAD(self):
        print "send header"
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        print "send header"
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        username = 'admin'
        password = 'changeme'
        encoded_password = base64.b64encode(username + ":" + password)
        
        ''' Present frontpage with user authentication. '''
        if self.headers.getheader('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received')
            pass
        elif self.headers.getheader('Authorization') == ('Basic ' + encoded_password):
            self.do_HEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('authenticated!')
            
            with open( os.path.join("web_files", "adsl_modem.html"), "r") as webfile:
                self.wfile.write(webfile.read())#.replace('\n', '')
            
            pass
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('not authenticated')
            pass
     
def get_server(port):
    """
    Call httpd.shutdown() to stop the server
    """
    
    httpd = SocketServer.TCPServer(("", port), Handler)
    return httpd
