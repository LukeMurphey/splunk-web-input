try:
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
except:
    from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import base64
import cgi
import random
try:
    from urllib.parse import urlparse, parse_qs
except ImportError:
    from urlparse import urlparse
    from urlparse import parse_qs
    

DEBUG_LOG = False

with open(os.path.join("web_files", "lorem_ipsum.txt"), "r") as webfile:
    LOREM_IPSUM = webfile.read()

class TestWebServerHandler(BaseHTTPRequestHandler):
    """
    Main class to present web-pages for testing purposes
    """
    def do_HEAD(self, size=None):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        if size is not None:
            self.send_header('Content-length', str(size))
        self.end_headers()

    def do_HEAD_utf8_encoding(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()

    def do_HEAD_bad_encoding(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=3Dutf-8=')
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

    def do_NOTFOUND(self):
        self.send_response(404)
        self.end_headers()

    def do_SENDCOOKIE(self):
        self.send_response(200)
        self.send_header('Set-Cookie', 'sessionid=ABCD')
        self.end_headers()

    def is_authenticated(self):
        cookie = self.headers.getheader('cookie')

        if not cookie:
            if DEBUG_LOG:
                print("Cookie is not present; user is not authenticated")
        elif cookie == 'sessionid=ABCD':
            if DEBUG_LOG:
                print("Cookie is present; user is authenticated")
            return True
        else:
            if DEBUG_LOG:
                print("Cookie is present but wrong; user is not authenticated")
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
                print("username is wrong")
            login_failed = True

        # Check the password
        if postvars.get("password", [None])[0] != 'changeme':
            if DEBUG_LOG:
                print("password is wrong")
            login_failed = True

        # Check the authenticity token
        if postvars.get("authenticity_token", [None])[0] != 'TMTEyUewsdg8F2fut7pe8yZ1zWwi8Mynrylq4PaWXL0tRf9jQ4q9Q/Hx0ExSwAfme/iPWw2dsWXlX65c86czwg==':
            if DEBUG_LOG:
                print("authenticity token is wrong")
            login_failed = True

        if login_failed:
            return False
        else:
            return True

    def create_html_with_links(self, links):

        html = '<html><body>'

        for link in links:
            html += '<a href="%s">Link</a>' % link

        html += '</body></html>'

        return html

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

        if self.path is not None:
            basepath = self.path.split("?")[0]
        else:
            basepath = None

        # No path provided
        if basepath is None:
            pass

        # Present header reflection page
        elif basepath == "/header_reflection":
            self.do_HEAD()
            self.wfile.write('<html><body><div class="user-agent">%s</div></body></html>' % str(self.headers['user-agent']))

        # Present XML file
        elif basepath== "/xml":
            self.do_HEAD()
            with open(os.path.join("web_files", "file.xml"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present HTML file
        elif basepath == "/html":
            self.do_HEAD()
            with open(os.path.join("web_files", "simple.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present HTML file with UTF-8 content
        elif basepath == "/utf8":
            self.do_HEAD()
            with open(os.path.join("web_files", "utf8.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present HTML file with a meta tag noting the content-type
        elif basepath == "/utf8_meta":
            self.do_HEAD()
            with open(os.path.join("web_files", "utf8_meta.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present HTML file and a header saying it is UTF-8
        elif basepath == "/utf8_header":
            self.do_HEAD_utf8_encoding()
            with open(os.path.join("web_files", "simple.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present HTML file with XML
        elif basepath == "/xml_with_encoding":
            self.do_HEAD()
            with open(os.path.join("web_files", "xml_with_encoding.xml"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present simulated view with sub-directories
        elif basepath == "/page_":
            self.do_HEAD()
            self.wfile.write()

        # Present HTML file with lots of links
        elif basepath == "/links":
            self.do_HEAD()

            html = """
<html>
    <body>"""

            for i in range(1, 10):
                random_number = str(random.randint(1,100000000))
                html += str(i) + ' <a href="/links?random=' + random_number + '">Link ' + random_number + '</a><br/>'

            html += LOREM_IPSUM

            html += """
    </body>
</html>"""

            self.wfile.write(html)

        # Present bad encoding
        elif basepath == "/bad_encoding":
            self.do_HEAD_bad_encoding()
            with open(os.path.join("web_files", "simple.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present HTML file for login
        elif basepath == "/login":
            self.do_HEAD()
            with open(os.path.join("web_files", "login_form.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present HTML file for login with overlapping field names
        elif basepath == "/login_overlapping_names":
            self.do_HEAD()
            with open(os.path.join("web_files", "login_form_overlapping_names.html"), "r") as webfile:
                self.wfile.write(webfile.read())

        # Present the authenticated form
        elif basepath == "/authenticated":
            if self.is_authenticated():
                self.do_HEAD()
                with open(os.path.join("web_files", "authenticated.html"), "r") as webfile:
                    self.wfile.write(webfile.read())
            else:
                self.do_AUTHFAILED()
                with open(os.path.join("web_files", "login_form.html"), "r") as webfile:
                    self.wfile.write(webfile.read())

        # Present a file of requested size (can be an unlimited large file if the size parameter
        # isn't provided)
        elif basepath == "/bigfile":

            # Get the file size
            parsed_path = urlparse(self.path)  
            parsed_args = parse_qs(parsed_path.query)
            size_limit = parsed_args.get('size', [None])[0]

            self.do_HEAD(size_limit)

            # Write out the file
            bytes_written = 0

            while size_limit is None or bytes_written < size_limit:
                random_number = random.randint(0,9)
                self.wfile.write(format(random_number, '01'))

                bytes_written = bytes_written + 1

        elif basepath == "/favicon.ico":
            self.do_NOTFOUND()

        # Present frontpage with user authentication.
        elif self.headers.getheader('Authorization') == None:
            self.do_AUTHHEAD()
            self.wfile.write('no auth header received')
            if DEBUG_LOG:
                print('no auth header received')

        elif self.headers.getheader('Authorization') == ('Basic ' + encoded_password):
            self.do_HEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('authenticated!')
            
            with open(os.path.join("web_files", "adsl_modem.html"), "r") as webfile:
                self.wfile.write(webfile.read())#.replace('\n', '')

            if DEBUG_LOG:
                print('auth header was correct:', self.headers.getheader('Authorization'))

        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.getheader('Authorization'))
            self.wfile.write('not authenticated')
            
            if DEBUG_LOG:
                print('auth header was wrong:', self.headers.getheader('Authorization'))

if __name__ == "__main__":
    server_address = ('127.0.0.1', 8080)
    httpd = HTTPServer(server_address, TestWebServerHandler)
    httpd.serve_forever()
