from BaseHTTPServer import BaseHTTPRequestHandler
import os
import base64
import cgi

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

    def do_AUTHFAILED(self):
        self.send_response(401)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_SENDCOOKIE(self):
        self.send_response(200)
        self.send_header('Set-Cookie', 'ABCD')
        self.end_headers()

    def is_authenticated(self):
        cookie = self.headers.getheader('cookie')

        if cookie and cookie == 'ABCD':
            return True
        else:
            return False

    def authenticate(self):
        ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))

        if ctype == 'multipart/form-data':
            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers.getheader('content-length'))
            postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
        else:
            postvars = {}

        login_failed = False

        # Check the username
        if postvars.get("username", [None])[0] != 'admin':
            if DEBUG_LOG:
                print "username is wrong"
            login_failed = True

        # Check the password
        if postvars.get("password", [None])[0] != 'changeme':
            if DEBUG_LOG:
                print "password is wrong"
            login_failed = True

        # Check the authenticity token
        if postvars.get("authenticity_token", [None])[0] != 'TMTEyUewsdg8F2fut7pe8yZ1zWwi8Mynrylq4PaWXL0tRf9jQ4q9Q/Hx0ExSwAfme/iPWw2dsWXlX65c86czwg==':
            if DEBUG_LOG:
                print "authenticity token is wrong"
            login_failed = True

        if login_failed:
            return False
        else:
            return True

    def do_POST(self):

        # The authentication form
        if self.path == "/login":

            authenticated_successfully = self.authenticate()

            # Return the appropriate error code
            if not authenticated_successfully:
                self.do_AUTHFAILED()
            else:
                self.do_SENDCOOKIE()

            # Render the login form
            with open(os.path.join("web_files", "login_form.html"), "r") as webfile:
                self.wfile.write(webfile.read())

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
                self.wfile.write(webfile.read())

        # Present HTML file
        elif self.path == "/html":
            self.do_HEAD()
            with open(os.path.join("web_files", "simple.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present HTML file for login
        elif self.path == "/login":
            self.do_HEAD()
            with open(os.path.join("web_files", "login_form.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present HTML file for login with overlapping field names
        elif self.path == "/login_overlapping_names":
            self.do_HEAD()
            with open(os.path.join("web_files", "login_form_overlapping_names.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present the authenticated form
        elif self.path == "/authenticated":
            if self.is_authenticated():
                self.do_HEAD()
                with open(os.path.join("web_files", "authenticated.html"), "r") as webfile:
                    self.wfile.write(webfile.read())
            else:
                self.do_HEAD()
                with open(os.path.join("web_files", "login_form.html"), "r") as webfile:
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
