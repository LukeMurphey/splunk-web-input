from BaseHTTPServer import BaseHTTPRequestHandler
import os
import base64

DEBUG_LOG = False

class TestWebServerHandler(BaseHTTPRequestHandler):
    """
    Main class to present web-pages for testing purposes
    """
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Test\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        username = 'admin'
        password = 'changeme'

        encoded_password = base64.b64encode(username + ":" + password)

        # No path provided
        if self.path is None:
            pass

        # Present header reflection page
        elif self.path == "/header_reflection":
            self.do_HEAD()
            self.wfile.write('<html><body><div class="user-agent">%s</div></body></html>' % str(self.headers['user-agent']))

        # Present XML file
        elif self.path == "/xml":
            self.do_HEAD()
            with open(os.path.join("web_files", "file.xml"), "r") as webfile:
                self.wfile.write(webfile.read())#.replace('\n', '')

        # Present HTML file
        elif self.path == "/html":
            self.do_HEAD()
            with open(os.path.join("web_files", "simple.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present frontpage with user authentication.
        elif self.headers.getheader('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received')
            if DEBUG_LOG:
                print 'no auth header received'

        elif self.headers.getheader('Authorization') == ('Basic ' + encoded_password):
            self.do_HEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('authenticated!')
            
            with open(os.path.join("web_files", "adsl_modem.html"), "r") as webfile:
                self.wfile.write(webfile.read())#.replace('\n', '')

            if DEBUG_LOG:
                print 'auth header was correct:', self.headers.getheader('Authorization')

        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('not authenticated')
            
            if DEBUG_LOG:
                print 'auth header was wrong:', self.headers.getheader('Authorization')
