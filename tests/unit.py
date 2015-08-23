# coding=utf-8
import unittest
import sys
import os
import time
import shutil
import re
import tempfile
import threading
import unicodedata
from StringIO import StringIO

sys.path.append( os.path.join("..", "src", "bin") )
sys.path.append( os.path.join("..", "src", "bin", "website_input_app") )

from web_input import URLField, DurationField, SelectorField, WebInput
from modular_input import Field, FieldValidationException

from test_web_server import get_server

class TestURLField(unittest.TestCase):
    
    def test_url_field_valid(self):
        url_field = URLField( "test_url_field_valid", "title", "this is a test" )
        
        self.assertEqual( url_field.to_python("http://google.com").geturl(), "http://google.com" )
        self.assertEqual( url_field.to_python("http://google.com/with/path").geturl(), "http://google.com/with/path" )
        self.assertEqual( url_field.to_python("http://google.com:8080/with/port").geturl(), "http://google.com:8080/with/port" )
        
    def test_url_field_invalid(self):
        url_field = URLField( "test_url_field_invalid", "title", "this is a test" )
        
        self.assertRaises( FieldValidationException, lambda: url_field.to_python("hxxp://google.com") )
        self.assertRaises( FieldValidationException, lambda: url_field.to_python("http://") )
        self.assertRaises( FieldValidationException, lambda: url_field.to_python("google.com") )
    
class TestDurationField(unittest.TestCase):
    
    def test_duration_valid(self):
        duration_field = DurationField( "test_duration_valid", "title", "this is a test" )
        
        self.assertEqual( duration_field.to_python("1m"), 60 )
        self.assertEqual( duration_field.to_python("5m"), 300 )
        self.assertEqual( duration_field.to_python("5 minute"), 300 )
        self.assertEqual( duration_field.to_python("5"), 5 )
        self.assertEqual( duration_field.to_python("5h"), 18000 )
        self.assertEqual( duration_field.to_python("2d"), 172800 )
        self.assertEqual( duration_field.to_python("2w"), 86400 * 7 * 2 )
        
    def test_url_field_invalid(self):
        duration_field = DurationField( "test_url_field_invalid", "title", "this is a test" )
        
        self.assertRaises( FieldValidationException, lambda: duration_field.to_python("1 treefrog") )
        self.assertRaises( FieldValidationException, lambda: duration_field.to_python("minute") )   
    
class TestWebInput(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        
        attempts = 0
        cls.httpd = None
        
        sys.stdout.write("Waiting for web-server to start ...")
        sys.stdout.flush()
        
        while cls.httpd is None and attempts < 20:
            try:
                cls.httpd = get_server(8888)
                
                print " Done"
            except IOError:
                cls.httpd = None
                time.sleep(2)
                attempts = attempts + 1
                sys.stdout.write(".")
                sys.stdout.flush()
        
        def start_server(httpd):
            httpd.serve_forever()
        
        t = threading.Thread(target=start_server, args = (cls.httpd,))
        t.daemon = True
        t.start()
        
    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
    
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp( prefix="TestWebInput" )
        #os.makedirs(self.tmp_dir)
        
    def tearDown(self):
        shutil.rmtree( self.tmp_dir )
    
    def get_test_dir(self):
        return os.path.dirname(os.path.abspath(__file__))
    
    def test_get_file_path(self):
        self.assertEquals( WebInput.get_file_path( "/Users/lmurphey/Applications/splunk/var/lib/splunk/modinputs/web_input", "web_input://TextCritical.com"), "/Users/lmurphey/Applications/splunk/var/lib/splunk/modinputs/web_input/2c70b6c76574eb4d825bfb194a460558.json")
        
    def test_input_timeout(self):
        url_field = URLField( "test_input_timeout", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("https://192.168.30.23/"), selector_field.to_python("div"), timeout=3 )
        
        self.assertEquals(result['timed_out'], True)
        
    def test_save_checkpoint(self):
        WebInput.save_checkpoint_data(self.tmp_dir, "web_input://TextCritical.com", { 'last_run': 100 })
        self.assertEquals( WebInput.last_ran(self.tmp_dir, "web_input://TextCritical.com"), 100)
        
    def test_is_expired(self):
        self.assertFalse( WebInput.is_expired(time.time(), 30) )
        self.assertTrue( WebInput.is_expired(time.time() - 31, 30) )
    
    def test_needs_another_run(self):
        
        # Test case where file does not exist
        self.assertTrue( WebInput.needs_another_run( "/Users/lmurphey/Applications/splunk/var/lib/splunk/modinputs/web_input", "web_input://DoesNotExist", 60 ) )
        
        # Test an interval right at the earlier edge
        self.assertFalse( WebInput.needs_another_run( os.path.join( self.get_test_dir(), "configs" ), "web_input://TextCritical.com", 60, 1365486765 ) )
        
        # Test an interval at the later edge
        self.assertFalse( WebInput.needs_another_run( os.path.join( self.get_test_dir(), "configs" ), "web_input://TextCritical.com", 10, 1365486775 ) )
        
        # Test interval beyond later edge
        self.assertTrue( WebInput.needs_another_run( os.path.join( self.get_test_dir(), "configs" ), "web_input://TextCritical.com", 10, 1365486776 ) )
    
    def test_scrape_page(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://textcritical.net/"), selector_field.to_python(".hero-unit.main_background") )
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 1)
        
    def test_scrape_page_child_text(self):
        # This text ensure that text from nodes under the selected nodes is properly extracted
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://textcritical.net/"), selector_field.to_python(".hero-unit.main_background"), output_matches_as_mv=True )
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 1)
        
        self.assertEqual(result['match'][0], "Ancient Greek, Modern Design TextCritical.net is a website that provides a library of ancient Greek works")
        
    def test_scrape_page_mv(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://textcritical.net/"), selector_field.to_python("h2"), output_matches_as_mv=True )
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 3)
        
        out = StringIO()
        web_input.output_event(result, stanza="web_input://textcritical_net", index="main", source="test_web_input", sourcetype="sourcetype", out=out)
        self.assertEquals( len(re.findall("match=", out.getvalue())), 3)
        
    def test_scrape_unavailable_page(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://192.168.30.23/"), selector_field.to_python(".hero-unit.main_background"), timeout=3 )
        
        self.assertEqual(result['timed_out'], True)
        
    def test_scrape_page_with_credentials(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://127.0.0.1:8888"), selector_field.to_python("tr"), username="admin", password="changeme", timeout=3, output_matches_as_mv=True )
        
        #print result['match']
        self.assertEqual(len(result['match']), 30)
        
    def test_scrape_page_with_invalid_credentials(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://127.0.0.1:8888"), selector_field.to_python("tr"), timeout=3, output_matches_as_mv=True )
        
        #print result['match']
        self.assertEqual(len(result['match']), 0)
    
    def test_unparsable(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://textcritical.net/media/images/link_external.png"), selector_field.to_python(".hero-unit .main_background"), timeout=3, output_matches_as_mv=True )
        self.assertEqual(result['match'], [])
        
    def test_scrape_encoding_detect_page(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://textcritical.net/work/new-testament/Mark/1/2?async"), selector_field.to_python(".verse-container") )
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 45)
        #print result['match']
        self.assertEqual(unicodedata.normalize('NFC', result['match'][1]), unicodedata.normalize('NFC', u"2 Καθὼς γέγραπται ἐν τῷ Ἠσαίᾳ τῷ προφήτῃ Ἰδοὺ ἀποστέλλω τὸν ἄγγελόν μου πρὸ προσώπου σου , ὃς κατασκευάσει τὴν ὁδόν σου :"))
        self.assertEqual(result['encoding'], "utf-8")
                
    def test_scrape_encoding_detect_sniff(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://textcritical.net/work/new-testament/Mark/1/2?async"), selector_field.to_python(".verse-container"), charset_detect_meta_enabled=False, charset_detect_content_type_header_enabled=False, charset_detect_sniff_enabled=True )
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 45)
        self.assertEqual(result['encoding'], "utf-8")
        
    def test_scrape_encoding_detect_meta(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://textcritical.net/work/new-testament/Mark/1/2"), selector_field.to_python(".verse-container"), charset_detect_meta_enabled=True, charset_detect_content_type_header_enabled=False, charset_detect_sniff_enabled=False )
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(result['encoding'], "utf-8")
    
    def test_scrape_encoding_detect_content_type_header(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://textcritical.net/work/new-testament/Mark/1/2?async"), selector_field.to_python(".verse-container"), charset_detect_meta_enabled=False, charset_detect_content_type_header_enabled=True, charset_detect_sniff_enabled=False )
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 45)
        self.assertEqual(result['encoding'], "utf-8")
    
    def test_scrape_page_adjacent_selector(self):
        # For bug: http://lukemurphey.net/issues/773
        
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://textcritical.net/"), selector_field.to_python("h1+p,.sharing-buttons"), timeout=3, output_matches_as_mv=True )
        self.assertEqual(len(result['match']), 2)
    
    def test_scrape_page_name_attributes(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://127.0.0.1:8888"), selector_field.to_python(".hd"), username="admin", password="changeme", timeout=3, name_attributes=["class"] )
        
        self.assertEqual(len(result['hd']), 31)
        
    def test_scrape_page_name_attributes_separate_fields(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://127.0.0.1:8888"), selector_field.to_python(".hd"), username="admin", password="changeme", timeout=3, name_attributes=["class"], output_matches_as_separate_fields=True, output_matches_as_mv=False)
        
        self.assertEqual(result['match_hd_1'], 'Mode:')
    
    def test_scrape_page_name_attributes_escaped_name(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://127.0.0.1:8888"), selector_field.to_python("input"), username="admin", password="changeme", timeout=3, name_attributes=["onclick"], include_empty_matches=True)
        
        self.assertTrue('btnBerTest__' in result)
        self.assertTrue('btnReset__' in result)
        
    def test_field_escaping(self):
        self.assertTrue(WebInput.escape_field_name("tree()"), "tree__")
        
    def test_field_escaping_whitespace(self):
        self.assertTrue(WebInput.escape_field_name("  "), "blank")
        
    def test_field_escaping_reserved(self):
        self.assertTrue(WebInput.escape_field_name("source"), "match_source")
        self.assertTrue(WebInput.escape_field_name("host"), "match_host")
        self.assertTrue(WebInput.escape_field_name("sourcetype"), "match_sourcetype")
        self.assertTrue(WebInput.escape_field_name("_time"), "match_time")
    
    def test_scrape_page_bad_encoding(self):
        #http://lukemurphey.net/issues/987
        
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://rss.slashdot.org/Slashdot/slashdot"), selector_field.to_python("description") )
        self.assertEqual(result['response_code'], 200)
        self.assertGreater(len(result['match']), 0)
        self.assertEqual(result['encoding'], "ISO-8859-1")
        
    def test_scape_page_custom_user_agent(self):
        web_input = WebInput(timeout=3)
        
        url_field = URLField( "test_web_input", "title", "this is a test" )
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test" )
        result = WebInput.scrape_page( url_field.to_python("http://127.0.0.1:8888/header_reflection"), selector_field.to_python(".user-agent"), timeout=3, output_matches_as_mv=True, user_agent="test_scape_page_custom_user_agent")
        print result
        
        #print result['match']
        self.assertEqual(len(result['match']), 1)
        self.assertEqual(result['match'][0], "test_scape_page_custom_user_agent")
        
    '''
    def test_html_to_json(self):
        
        web_input = WebInput(timeout=3)
        
        content = """
        <html>
            <head>
              <title>Some page</title>
            </head>
            <body>
              <div class="header">This is the header</div>
              <div class="footer" />
            </body>
        </html>
        """
        
        tree = lxml.html.fromstring(content)
        
        html_as_json = WebInput.html_to_json(tree)
    '''
        
if __name__ == "__main__":
    loader = unittest.TestLoader()
    suites = []
    suites.append(loader.loadTestsFromTestCase(TestWebInput))
    
    unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(suites))