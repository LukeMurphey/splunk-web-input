# coding=utf-8
"""
This class includes the tests for Website Input.

Below are the list of test-cases. The release where the related feature was included is in
parenthesis:

 * TestURLField: tests the URL field that is used in modular inputs
 * TestDurationField: tests the duration field that is used in modular inputs
 * TestWebInput: tests of the core of the WebInput an WebScraper classes
 * TestWebInputCrawling: tests the ability to spider through several pages (2.0)
 * TestRawContent: tests the returning of raw content (2.1)
 * TestCustomSeparator: test the use of a custom separator between results (2.1)
 * TestWebClient: tests the WebClient web client abstraction layer (4.4)
 * TestBrowserRendering: tests the abilty to get content from a browser (3.0)
 * TestBrowserRenderingFirefox: same as above but using Firefox (3.0)
 * TestBrowserRenderingChrome: same as above but using Chrome (4.3)
 * TestHashHelper: tests the ability to calculate a hash on the results (3.0)
 * TestWebDriverClient: tests the client that wraps the Selenium web-driver (4.4)
 * TestFormAuthentication: tests the use of forms style authentication (4.4)
 * TestFormAuthenticationFirefox: same as above but using Firefox (4.5)
 * TestFormAuthenticationChrome: same as above but using Chrome (4.5)

Below are some details regarding how you can run these tests:

 1) Running tests selectively from the CLI
    You can run individual tests from the command-line by passing in the name of the test suite
    or the test in order to run only part of the tests, like this:

         splunk_py unit.py TestFormAuthenticationChrome

         splunk_py unit.py TestWebInput.test_input_timeout

    Note that tests need to be run from the "tests" directory.

  2) Running tests only for particular browsers
     By default, the test suite will run all tests inckuding those for Firefox and Chrome. These
     other browsers require you to have them installed. If you want to avoid running tests against
     one or more of these browsers then you can set the TEST_BROWSERS environment variable with a
     list of the browsers you want to run against.

     Below is a an example of setting TEST_BROWSERS in bash such that tests run against Firefox
     only (avoiding the Chrome tests):

        export TEST_BROWSERS=firefox

     Below is a an example that runs tests against both Firefox and Chrome (BTW: this is default
     behavior the occurs when TEST_BROWSERS isn't set at all)

        export TEST_BROWSERS=firefox,chrome

  3) Outputting test results in JUnit format (so that CI tools can read them)
     You have the test script create output in JUnit format by setting the file name where you want
     the output to go.
     
     Below is an example of setting TEST_OUTPUT in bash that will cause the tester to output the
     results in "tmp/results.xml": 

        export TEST_OUTPUT=tmp/results.xml

    Note that the paths are relative to the root of the source-code directory.

"""

import unittest
import sys
import os
import errno
import time
import shutil
import re
import tempfile
import unicodedata
import lxml.html

try: 
    from StringIO import StringIO
except:
    from io import StringIO

from collections import OrderedDict

# Change into the tests directory if necessary
# This is necessary when tests are executed from the main directory as opposed to the tests
# directory.
if not os.getcwd().endswith("tests"):
    os.chdir("tests")

sys.path.append(os.path.join("..", "src", "bin"))
sys.path.append(os.path.join("..", "src", "bin", "website_input_app"))

from web_input import URLField, DurationField, SelectorField, WebInput, WebScraper
from web_client import MechanizeClient
from web_driver_client import WebDriverClient, FirefoxClient, ChromeClient
from website_input_app import hash_helper
from unit_test_web_server import UnitTestWithWebServer, skipIfNoServer

path_to_mod_input_lib = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modular_input.zip')
sys.path.insert(0, path_to_mod_input_lib)
from modular_input import  Field, FieldValidationException

class TestURLField(unittest.TestCase):

    def test_url_field_valid(self):
        url_field = URLField("test_url_field_valid", "title", "this is a test")

        self.assertEqual(url_field.to_python("http://google.com").geturl(), "http://google.com")
        self.assertEqual(url_field.to_python("http://google.com/with/path").geturl(), "http://google.com/with/path")
        self.assertEqual(url_field.to_python("http://google.com:8080/with/port").geturl(), "http://google.com:8080/with/port")

    def test_url_field_invalid(self):
        url_field = URLField("test_url_field_invalid", "title", "this is a test")

        self.assertRaises(FieldValidationException, lambda: url_field.to_python("hxxp://google.com"))
        self.assertRaises(FieldValidationException, lambda: url_field.to_python("http://"))
        self.assertRaises(FieldValidationException, lambda: url_field.to_python("google.com"))

class TestDurationField(unittest.TestCase):

    def test_duration_valid(self):
        duration_field = DurationField("test_duration_valid", "title", "this is a test")

        self.assertEqual(duration_field.to_python("1m"), 60)
        self.assertEqual(duration_field.to_python("5m"), 300)
        self.assertEqual(duration_field.to_python("5 minute"), 300)
        self.assertEqual(duration_field.to_python("5"), 5)
        self.assertEqual(duration_field.to_python("5h"), 18000)
        self.assertEqual(duration_field.to_python("2d"), 172800)
        self.assertEqual(duration_field.to_python("2w"), 86400 * 7 * 2)

    def test_url_field_invalid(self):
        duration_field = DurationField("test_url_field_invalid", "title", "this is a test")

        self.assertRaises(FieldValidationException, lambda: duration_field.to_python("1 treefrog"))
        self.assertRaises(FieldValidationException, lambda: duration_field.to_python("minute"))

class TestWebInput(UnitTestWithWebServer):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="TestWebInput")
        #os.makedirs(self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def get_test_dir(self):
        return os.path.dirname(os.path.abspath(__file__))

    def test_get_file_path(self):

        file_path = WebInput.get_file_path("/Users/lmurphey/Applications/splunk/var/lib/splunk/modinputs/web_input", "web_input://TextCritical.com")
        expected_path = os.path.join("/Users/lmurphey/Applications/splunk/var/lib/splunk/modinputs/web_input", "2c70b6c76574eb4d825bfb194a460558.json")
        self.assertEquals(file_path, expected_path)

    def test_input_timeout(self):
        url_field = URLField("test_input_timeout", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("https://192.168.30.23/"), selector_field.to_python("div"))
        result = results[0]
        self.assertEquals(result['timed_out'], True)

    def test_save_checkpoint(self):

        web_input = WebInput(timeout=3)

        web_input.save_checkpoint_data(self.tmp_dir, "web_input://TextCritical.com", {'last_run': 100})
        self.assertEquals(WebInput.last_ran(self.tmp_dir, "web_input://TextCritical.com"), 100)

    def test_is_expired(self):
        self.assertFalse(WebInput.is_expired(time.time(), 30))
        self.assertTrue(WebInput.is_expired(time.time() - 31, 30))

    def test_needs_another_run(self):

        # Test case where file does not exist
        self.assertTrue(WebInput.needs_another_run("/Users/lmurphey/Applications/splunk/var/lib/splunk/modinputs/web_input", "web_input://DoesNotExist", 60))

        # Test an interval right at the earlier edge
        self.assertFalse(WebInput.needs_another_run(os.path.join(self.get_test_dir(), "configs"), "web_input://TextCritical.com", 60, 1365486765))

        # Test an interval at the later edge
        self.assertFalse(WebInput.needs_another_run(os.path.join(self.get_test_dir(), "configs"), "web_input://TextCritical.com", 10, 1365486775))

        # Test interval beyond later edge
        self.assertTrue(WebInput.needs_another_run(os.path.join(self.get_test_dir(), "configs"), "web_input://TextCritical.com", 10, 1365486776))

    def test_scrape_page(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_scrape_page", "title", "this is a test")

        web_scraper = WebScraper()
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python(".ab"))
        result = results[0]
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 1)

    def test_scrape_page_child_text(self):
        # This text ensure that text from nodes under the selected nodes is properly extracted
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_scrape_page_child_text", "title", "this is a test")

        web_scraper = WebScraper()
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python(".ab"), output_matches_as_mv=True)
        result = results[0]
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 1)

        self.assertEqual(result['match'][0], "Text_1")

    def test_scrape_page_mv(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_scrape_page_mv", "title", "this is a test")

        web_scraper = WebScraper()
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python(".b > div"), output_matches_as_mv=True)

        result = results[0]
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 4)

        out = StringIO()
        web_input = WebInput(timeout=3)
        web_input.output_event(result, stanza="web_input://textcritical_net", index="main", source="test_web_input", sourcetype="sourcetype", out=out)
        self.assertEquals(len(re.findall("match=", out.getvalue())), 4)

    def test_scrape_unavailable_page(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.2/"), selector_field.to_python("div"))
        print(results)
        result = results[0]
        self.assertEqual(result['timed_out'], True)

    @skipIfNoServer
    def test_scrape_page_with_credentials(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        web_scraper.set_authentication(username="admin", password="changeme")
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port)), selector_field.to_python("tr"), output_matches_as_mv=True)        
        #results = web_scraper.scrape_page(url_field.to_python("http://httpbin.org/basic-auth/admin/changeme"), selector_field.to_python("tr"), username="admin", password="changeme", output_matches_as_mv=True)

        result = results[0]
        #print(result['match'])
        self.assertEqual(len(result['match']), 30)
        
    @skipIfNoServer
    def test_scrape_page_with_invalid_credentials(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port)), selector_field.to_python("tr"), output_matches_as_mv=True)
        result = results[0]
        #print(result['match'])
        self.assertEqual(len(result.get('match', '')), 0)

    @skipIfNoServer
    def test_scrape_page_with_case_insensitive_selector(self):
        # https://lukemurphey.net/issues/1739
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python("H1"), output_matches_as_mv=True)
        result = results[0]

        self.assertEqual(len(result['match']), 1)

    def test_unparsable(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://textcritical.net/media/images/link_external.png"), selector_field.to_python(".hero-unit .main_background"), output_matches_as_mv=True)
        result = results[0]
        self.assertEqual(result['match'], [])

    def test_scrape_encoding_detect_page(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/utf8"), selector_field.to_python(".ab"))
        result = results[0]
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 1)
        #print(result['match'])
        self.assertEqual(unicodedata.normalize('NFC', result['match'][0]), unicodedata.normalize('NFC', u"ΕΝ ΑΡΧΗ ἦν ὁ λόγος, καὶ ὁ λόγος ἦν πρὸς τὸν θεόν, καὶ θεὸς ἦν ὁ λόγος."))
        self.assertEqual(result['encoding'], "utf-8")

    def test_scrape_encoding_detect_sniff(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        # Enable only sniffing
        web_scraper.set_charset_detection(False, False, True)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/utf8"), selector_field.to_python("div"))
        result = results[0]

        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 8)
        self.assertEqual(result['encoding'], "utf-8")

    def test_scrape_encoding_detect_meta(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper()
        # Enable only meta detection
        web_scraper.set_charset_detection(True, False, False)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/utf8_meta"), selector_field.to_python("div"))
        result = results[0]

        self.assertEqual(result['response_code'], 200)
        self.assertEqual(result['encoding'], "UTF-8")

    def test_scrape_encoding_detect_content_type_header(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        # Enable only content-type detection
        web_scraper = WebScraper()
        web_scraper.set_charset_detection(False, True, False)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/utf8_header"), selector_field.to_python("div"))
        result = results[0]

        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 8)
        self.assertEqual(result['encoding'], "utf-8")

    def test_scrape_encoding_invalid(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_scrape_encoding_invalid", "title", "this is a test")

        # Enable only content-type detection
        web_scraper = WebScraper()
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python(".a > div"))
        result = results[0]

        self.assertEqual(result['response_code'], 200)
        self.assertEqual(len(result['match']), 2)
        self.assertEqual(result['encoding'], "ascii")

    def test_scrape_page_adjacent_selector(self):
        # For bug: http://lukemurphey.net/issues/773

        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_scrape_page_adjacent_selector", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python(".ba+div,.bd"), output_matches_as_mv=True)
        result = results[0]

        self.assertEqual(len(result['match']), 2)

    @skipIfNoServer
    def test_scrape_page_name_attributes(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        web_scraper.set_authentication("admin", "changeme")
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port)), selector_field.to_python(".hd"), name_attributes=["class"])
        result = results[0]

        self.assertEqual(len(result['hd']), 31)

    @skipIfNoServer
    def test_scrape_page_name_attributes_separate_fields(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        web_scraper.set_authentication(username="admin", password="changeme")
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port)), selector_field.to_python(".hd"), name_attributes=["class"], output_matches_as_separate_fields=True, output_matches_as_mv=False)
        result = results[0]

        self.assertEqual(result['match_hd_1'], 'Mode:')

    @skipIfNoServer
    def test_scrape_page_name_attributes_escaped_name(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        web_scraper.set_authentication("admin", "changeme")
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port)), selector_field.to_python("input"), name_attributes=["onclick"], include_empty_matches=True)
        result = results[0]

        self.assertTrue('btnBerTest__' in result)
        self.assertTrue('btnReset__' in result)

    @skipIfNoServer
    def test_scrape_page_include_empty_matches(self):
        # https://lukemurphey.net/issues/1726

        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField( "test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python(".a"), include_empty_matches=True, text_separator=",")
        result = results[0]

        # The result below includes more empty items than expected. This is because text nodes can occur after elements.
        # See the example below with the text nodes called out:
        #
        # <div class="a"> TEXT_NODE_1
        #     <div class="aa">TEXT_NODE_2</div> TEXT_NODE_3
        #     <div class="ab">Text_1</div> TEXT_NODE_5
        #     <div class="ac">Text_2</div> TEXT_NODE_7
        #     <div class="ad">TEXT_NODE_8</div> TEXT_NODE_9
        # </div>
        #
        self.assertEqual(result['match'][0], ',,,Text_1,,Text_2,,,')

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python(".b"), include_empty_matches=True, text_separator=",")
        result = results[0]

        self.assertEqual(result['match'][0], ',Text_0,,Text_1,,Text_2,,Text_3,')

    @skipIfNoServer
    def test_scrape_page_include_empty_matches_nulls(self):
        # https://lukemurphey.net/issues/1726

        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python(".a > *"), include_empty_matches=True, text_separator=",")

        result = results[0]
        self.assertEqual(result['match'][0], 'NULL')
        self.assertEqual(result['match'][1], 'Text_1')
        self.assertEqual(result['match'][2], 'Text_2')
        self.assertEqual(result['match'][3], 'NULL')

    def test_field_escaping(self):
        self.assertTrue(WebScraper.escape_field_name("tree()"), "tree__")

    def test_field_escaping_whitespace(self):
        self.assertTrue(WebScraper.escape_field_name("  "), "blank")

    def test_field_escaping_reserved(self):
        self.assertTrue(WebScraper.escape_field_name("source"), "match_source")
        self.assertTrue(WebScraper.escape_field_name("host"), "match_host")
        self.assertTrue(WebScraper.escape_field_name("sourcetype"), "match_sourcetype")
        self.assertTrue(WebScraper.escape_field_name("_time"), "match_time")

    def test_scrape_page_bad_encoding(self):
        #http://lukemurphey.net/issues/987

        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper()
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/xml_with_encoding"), selector_field.to_python("tree"))
        result = results[0]

        self.assertEqual(result['response_code'], 200)
        self.assertEqual(result['encoding'], "ascii")

    @skipIfNoServer
    def test_scrape_page_custom_user_agent(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        web_scraper.user_agent = "test_scrape_page_custom_user_agent"
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/header_reflection"), selector_field.to_python(".user-agent"), output_matches_as_mv=True)
        result = results[0]

        #print(result['match']
        self.assertEqual(len(result['match']), 1)
        self.assertEqual(result['match'][0], "test_scrape_page_custom_user_agent")
        
    @skipIfNoServer
    def test_scrape_page_xml(self):
        # http://lukemurphey.net/issues/1144
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/xml"), selector_field.to_python("COOK_TEMP"), output_matches_as_mv=True)
        result = results[0]

        self.assertEqual(len(result['match']), 1)
        self.assertEqual(result['match'][0], "695")

    @skipIfNoServer
    def test_scrape_page_names_as_tag_name(self):
        # http://lukemurphey.net/issues/1145
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/xml"), selector_field.to_python("COOK_TEMP"), output_matches_as_mv=True, use_element_name=True)
        result = results[0]

        self.assertEqual(len(result['match']), 1)
        self.assertEqual(result['match'][0], "695")
        self.assertEqual(len(result['cook_temp']), 1)
        self.assertEqual(result['cook_temp'][0], "695")

    @skipIfNoServer
    def test_scrape_page_match_prefix(self):

        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/xml"), selector_field.to_python("COOK_TEMP"), output_matches_as_mv=True, use_element_name=True, match_prefix="prefix_")
        result = results[0]

        self.assertEqual(len(result['prefix_cook_temp']), 1)
        self.assertEqual(result['prefix_cook_temp'][0], "695")

    @skipIfNoServer
    def test_scrape_page_match_prefix_with_multiple(self):
        # http://lukemurphey.net/issues/1628

        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/xml"), selector_field.to_python("MISC > *"), output_matches_as_mv=True, use_element_name=True, match_prefix="prefix_")
        result = results[0]

        self.assertEqual(len(result['prefix_string']), 3)
        self.assertEqual(result['prefix_string'][0], "ABC")
        self.assertEqual(result['prefix_string'][1], "DEF")
        self.assertEqual(result['prefix_string'][2], "GHI")

    @skipIfNoServer
    def test_scrape_page_output_fx(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_scrape_page_output_fx", "title", "this is a test")

        results = []
        output_fx = lambda result: results.append(result)

        web_scraper = WebScraper(timeout=3)
        web_scraper.set_authentication("admin", "changeme")
        results_count = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port)), selector_field.to_python(".hd"), name_attributes=["class"], output_fx=output_fx)

        self.assertEqual(results_count, 1)
        self.assertEqual(len(results[0]['hd']), 31)

    @skipIfNoServer
    def test_scrape_page_download_limit(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_scrape_page_download_limit", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/bigfile"), selector_field.to_python("*"))

        self.assertEqual(len(results), 1)

        self.assertEqual(len(results[0]['match']), 1)
        self.assertEqual(len(results[0]['match'][0]), 512000)

    def test_output_results_matches_unchanged(self):
        web_input = WebInput(timeout=3)
        web_input.OUTPUT_USING_STASH = False

        checkpoint_data = {
            'matches_hash' : '863eb10bc0bee8b54a93e1cc1a3075f43f8752a48e9b7ea605c2d58b'
        }

        results = [
            {
                'match' : ['tree', 'frog'],
                'response_time' : '1'
            }
        ]

        # Run the input so that the match_hashes are populated
        result_info = web_input.output_results(results, "main", "web_input://test_case", "web_input", "no_host", checkpoint_data, WebInput.OUTPUT_RESULTS_WHEN_MATCHES_CHANGE)

        self.assertEquals(result_info.results_outputted, 0)

        # We are going to test again with a result set that is equivalent in its matches to the
        # previous output and see if it correctly determines that the matches are the same.
        # To do this, we will create an identical result in terms of matches but different in the
        # response time. The response time should be allowed to be different while recognizing
        # that the matches are the same.
        results2 = [
            {
                'match' : ['tree', 'frog'],
                'response_time' : '2'
            }
        ]

        # Run the input and ensure that the matches are now ignored
        result_info = web_input.output_results(results2, "main", "web_input://test_case", "web_input", "no_host", checkpoint_data, WebInput.OUTPUT_RESULTS_WHEN_MATCHES_CHANGE)

        self.assertEquals(result_info.results_outputted, 0)

        # Run the input and ensure that the matches are not ignored now that the hash is different
        results3 = [
            {
                'match' : ['bull', 'frog'],
                'response_time' : '2'
            }
        ]

        result_info = web_input.output_results(results3, "main", "web_input://test_case", "web_input", "no_host", checkpoint_data, WebInput.OUTPUT_RESULTS_WHEN_MATCHES_CHANGE)

        self.assertEquals(result_info.results_outputted, 1)

    def test_output_results_hash_non_mv_matches(self):
        """
        This test makes sure that hashes are made when output is non-MV.
        """
        # https://lukemurphey.net/issues/2363
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_scrape_page", "title", "this is a test")

        web_scraper = WebScraper()
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python(".ab"), output_matches_as_mv=False)
        result = results[0]
        self.assertEqual(result['response_code'], 200)
        self.assertEqual(result['content_md5'], 'ccf5efbb669f49af10abc0751f896a4e')

    def test_output_results_non_mv(self):
        """
        Ensure that no error is thrown when results in OrderedDict format are sent
        """
        # https://lukemurphey.net/issues/2437
        web_input = WebInput(timeout=3)
        web_input.OUTPUT_USING_STASH = False

        results = [OrderedDict([('title', u'temp input test'), ('timed_out', True)])]

        # Run the input so that the match_hashes are populated
        result_info = web_input.output_results(results, "main", "web_input://test_case", "web_input", "no_host", {}, WebInput.OUTPUT_RESULTS_ALWAYS)

        self.assertEquals(result_info.results_outputted, 1)

class TestWebInputCrawling(UnitTestWithWebServer):
    """
    http://lukemurphey.net/issues/762
    """

    def test_cleanup_link(self):

        self.assertEqual(WebScraper.cleanup_link("http://textcritical.net/read#something", "http://textcritical.net/"), "http://textcritical.net/read")
        self.assertEqual(WebScraper.cleanup_link("read/", "http://textcritical.net/"), "http://textcritical.net/read/")
        self.assertEqual(WebScraper.cleanup_link("../read/", "http://textcritical.net/test/"), "http://textcritical.net/read/")
        self.assertEqual(WebScraper.cleanup_link("read#test", "http://textcritical.net/"), "http://textcritical.net/read")
        self.assertEqual(WebScraper.cleanup_link("read/", "http://textcritical.net/test/"), "http://textcritical.net/test/read/")

    def test_remove_anchor(self):

        self.assertEqual(WebScraper.remove_anchor("http://textcritical.net/read#something"), "http://textcritical.net/read")
        self.assertEqual(WebScraper.remove_anchor("http://textcritical.net/read/"), "http://textcritical.net/read/")

    def test_extract_links(self):

        tree = lxml.html.fromstring("""
        <!DOCTYPE html>
        <html>
        <body>
        
        <h1>Test</h1>
        
        <a>Test link[1]</a>
        <a href="http://textcritical.net">Test link[2]</a>
        <a href="link_3">Test link[3]</a>
        <a href="../link_4">Test link[4]</a>
        <a href="../link_4">Test duplicate link[4]</a>
        <a href="link_3#test">Test duplicate anchor link[3]</a>
        </body>
        </html>
        """)

        links = WebScraper.extract_links(tree, "http://textcritical.net/read/")

        self.assertEqual(len(links), 3)

        self.assertEqual(links[0], "http://textcritical.net")
        self.assertEqual(links[1], "http://textcritical.net/read/link_3")
        self.assertEqual(links[2], "http://textcritical.net/link_4")

    def test_extract_links_filter(self):

        tree = lxml.html.fromstring("""
        <!DOCTYPE html>
        <html>
        <body>
        
        <h1>Test</h1>
        
        <a>Test link[1]</a>
        <a href="http://textcritical.net">Test link[2]</a>
        <a href="link_3">Test link[3]</a>
        <a href="http://textcritical.com">Test link[3]</a>
        </body>
        </html>
        """)

        links = WebScraper.extract_links(tree, "http://textcritical.net/read/", url_filter="http://textcritical.net")

        self.assertEqual(len(links), 2)

        self.assertEqual(links[0], "http://textcritical.net")
        self.assertEqual(links[1], "http://textcritical.net/read/link_3")

    def test_extract_links_https_only(self):
        # https://lukemurphey.net/issues/1882

        tree = lxml.html.fromstring("""
        <!DOCTYPE html>
        <html>
        <body>
        
        <h1>Test</h1>
        
        <a>Test link[1]</a>
        <a href="https://textcritical.net">Test link[2]</a>
        <a href="link_3">Test link[3]</a>
        <a href="http://textcritical.com">Test link[3]</a>
        </body>
        </html>
        """)

        links = WebScraper.extract_links(tree, "https://textcritical.net/read/", url_filter="*", https_only=True)
        
        self.assertEqual(len(links), 2)
        self.assertEqual(links[0], "https://textcritical.net")
        self.assertEqual(links[1], "https://textcritical.net/read/link_3")

    def test_scrape_page_spider(self):
        # http://lukemurphey.net/issues/762

        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/links"), selector_field.to_python("a"), output_matches_as_mv=True, page_limit=5)
        result = results[0]

        self.assertEqual(len(results), 5)
        self.assertEqual(len(result['match']), 9)

    def test_scrape_page_spider_https_only(self):
        # http://lukemurphey.net/issues/1882

        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)

        results = web_scraper.scrape_page(url_field.to_python("http://textcritical.net"), selector_field.to_python(".footer-links > li > a"), https_only=True)

        self.assertEqual(len(results), 1)

    def test_is_url_in_url_filter(self):
        self.assertTrue(WebScraper.is_url_in_url_filter("http://textcritical.net/tree", "http://textcritical.net*"))
        self.assertTrue(WebScraper.is_url_in_url_filter("http://textcritical.net/tree", "http://textcritical.net/*"))
        self.assertFalse(WebScraper.is_url_in_url_filter("http://textcritical.net/", "http://textcritical.com/*"))
        self.assertTrue(WebScraper.is_url_in_url_filter("http://textcritical.com", "http://textcritical.*"))

    def test_scrape_page_spider_depth_limit(self):
        # http://lukemurphey.net/issues/1312

        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://textcritical.net"), selector_field.to_python(".footer-links > li > a"), output_matches_as_mv=True, page_limit=5, depth_limit=0)
        self.assertEqual(len(results), 1)

    def test_scrape_page_spider_from_non_matching_links(self):
        # http://lukemurphey.net/issues/1366

        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_web_input_css", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://textcritical.net"), selector_field.to_python(".ajah-loading"), output_matches_as_mv=True, page_limit=5, depth_limit=3)

        self.assertGreater(len(results), 1) # This should return only one result if link extraction only applies to matched pages 

class TestRawContent(UnitTestWithWebServer):
    """
    http://lukemurphey.net/issues/1168
    """

    @skipIfNoServer
    def test_get_raw_content(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_get_raw_content", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/xml"), selector_field.to_python("COOK_TEMP"), output_matches_as_mv=True, include_raw_content=True)
        result = results[0]

        self.assertEqual(len(results), 1)
        self.assertEqual(result['content'][0:15], "<nutcallstatus>")

    @skipIfNoServer
    def test_get_raw_content_empty_selector(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_get_raw_content_empty_selector", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/xml"), selector_field.to_python(""), output_matches_as_mv=True, include_raw_content=True)
        result = results[0]

        self.assertEqual(len(results), 1)
        self.assertEqual(result['content'][0:15], "<nutcallstatus>")

class TestCustomSeparator(UnitTestWithWebServer):
    """
    See http://lukemurphey.net/issues/763
    """
 
    @skipIfNoServer
    def test_custom_separator(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_custom_separator", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/xml"), selector_field.to_python("FOOD1"), output_matches_as_mv=True, text_separator=":")
        result = results[0]

        self.assertEqual(len(results), 1)
        self.assertEqual(result['match'][0], "Food1:OPEN:1800:4")

    def test_append_if_not_empty_both_have_values(self):
        self.assertEqual(WebScraper.append_if_not_empty("tree", "frog", ":"), "tree:frog")

    def test_append_if_first_has_value(self):
        self.assertEqual(WebScraper.append_if_not_empty("tree", "", ":"), "tree")

    def test_append_if_second_has_value(self):
        self.assertEqual(WebScraper.append_if_not_empty("", "frog", ":"), "frog")

    def test_append_if_neither_has_value(self):
        self.assertEqual(WebScraper.append_if_not_empty("", "", ":"), "")

class TestWebClient(UnitTestWithWebServer):
    """
    This is a class that supports running different web-clients for testing.
    """

    # Override this to test other browsers too (like Firfox)
    BROWSER = WebScraper.INTEGRATED_CLIENT # By default, test the internal browser
    client = None

    def get_client(self, browser):
        print(self.BROWSER)
        if self.BROWSER.lower() == WebScraper.INTEGRATED_CLIENT:
            self.client = MechanizeClient(5)
        elif self.BROWSER.lower() == WebScraper.FIREFOX:
            self.client = FirefoxClient(5)
        elif self.BROWSER.lower() == WebScraper.CHROME:
            self.client = ChromeClient(5)
        else:
            raise Exception("Browser not recognized")

        return self.client

    def setUp(self):
        browsers_to_test = os.environ.get('TEST_BROWSERS', None)

        # Change the strings to lowercase. This is important in case people specified the name in uppercase.
        if browsers_to_test is not None:
            browsers_to_test = browsers_to_test.lower()

        if browsers_to_test is None:
            # Test them all
            pass
        elif self.BROWSER.lower() == WebScraper.INTEGRATED_CLIENT:
            # Always run the internal client since it has no external dependencies
            pass
        elif not self.BROWSER in browsers_to_test:
            self.skipTest("Skipping this browser since it is not listed as a browser to test: " + self.BROWSER)

    def tearDown(self):
        if self.client is not None:
            self.client.close()
            self.client = None

        super(TestWebClient, self).tearDown()

class TestBrowserRendering(TestWebClient):
    """
    http://lukemurphey.net/issues/1323
    """

    @skipIfNoServer
    def test_scrape_page(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_custom_separator", "title", "this is a test")

        web_scraper = WebScraper(timeout=3)
        results = web_scraper.scrape_page(url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/html"), selector_field.to_python("h1"), output_matches_as_mv=True, browser=self.BROWSER)
        result = results[0]

        self.assertEqual(len(results), 1)
        self.assertEqual(result['match'][0], "Heading")
        self.assertEqual(result['browser'], self.BROWSER)

    @skipIfNoServer
    def test_get_result(self):

        # Don't execute this for the integrated client
        if self.BROWSER.lower() == WebScraper.INTEGRATED_CLIENT:
            return

        client = self.get_client(self.BROWSER)
        content = client.get_url("http://127.0.0.1:" + str(self.web_server_port) + "/html")

        self.assertEqual(content[0:5], '<html')

    @skipIfNoServer
    def test_get_result_basic_auth(self):

        # Don't execute this for the integrated client
        if self.BROWSER.lower() == WebScraper.INTEGRATED_CLIENT:
            return

        client = self.get_client(self.BROWSER)
        content = client.get_url("http://admin:changeme@127.0.0.1:" + str(self.web_server_port) + "/")

        self.assertGreaterEqual(content.find("Basic YWRtaW46Y2hhbmdlbWU=authenticated!"), 0)

    @skipIfNoServer
    def test_get_result_basic_auth_as_args(self):

        # Don't execute this for the integrated client
        if self.BROWSER.lower() == WebScraper.INTEGRATED_CLIENT:
            return

        client = self.get_client(self.BROWSER)
        client.setCredentials("admin", "changeme")
        content = client.get_url("http://127.0.0.1:" + str(self.web_server_port) + "/")

        self.assertGreaterEqual(content.find("Basic YWRtaW46Y2hhbmdlbWU=authenticated!"), 0)

class TestBrowserRenderingFirefox(TestBrowserRendering):
    BROWSER = WebScraper.FIREFOX

class TestBrowserRenderingChrome(TestBrowserRendering):
    BROWSER = WebScraper.CHROME

class TestHashHelper(unittest.TestCase):
    """
    https://lukemurphey.net/issues/1806
    """

    def test_hash_string(self):
        """
        Test hashing of a string.
        """

        data = "Test"

        self.assertEqual(
            hash_helper.hash_data(data),
            "3606346815fd4d491a92649905a40da025d8cf15f095136b19f37923"
        )

    def test_hash_dictionary(self):
        """
        Test hashing of a dictionary.
        This dictionary will include some odd cases such as:
            1) Integer values
            2) Key that are integers
            3) Values that include lists
        """

        data = {
            "A": "aaaa",
            "B": "bbbb",
            "One": 1,
            2: "Two",
            "list" : [1, 2, 3, 4]
        }

        self.assertEqual(
            hash_helper.hash_data(data),
            "2162da53bd7307db3595f0f3c8c845960cfbc1a707c1af513c66a1e2"
        )

    def test_hash_dictionary_sorting(self):
        """
        Test hashing of a dictionary and make sure that the dictionary is sorted so that two
        dictionaries with the same values in a different order are not considered different.
        """

        data = {
            "B": "bbbb",
            "A": "aaaa",
            "One": 1,
            2: "Two",
            "list" : [1, 2, 3, 4]
        }

        data2 = {
            2: "Two",
            "A": "aaaa",
            "B": "bbbb",
            "list" : [1, 2, 3, 4],
            "One": 1
        }

        pre_sorted = hash_helper.hash_data(data)
        post_sorted = hash_helper.hash_data(data2)

        self.assertEqual(pre_sorted, '2162da53bd7307db3595f0f3c8c845960cfbc1a707c1af513c66a1e2')
        self.assertEqual(pre_sorted, post_sorted)

    def test_hash_dictionary_with_list(self):
        """
        Test hashing of a dictionary and make sure that a list within the dictionary properly
        affects the hash.
        """

        data = {
            "B": "bbbb",
            "A": "aaaa",
            "One": 1,
            2: "Two",
            "list" : [1, 2, 3, 4]
        }

        data2 = {
            "B": "bbbb",
            "A": "aaaa",
            "One": 1,
            2: "Two",
            "list" : [1, 2, 3] # This was changed, should cause the hash to change
        }

        pre_sorted = hash_helper.hash_data(data)
        post_sorted = hash_helper.hash_data(data2)

        self.assertEqual(pre_sorted, '2162da53bd7307db3595f0f3c8c845960cfbc1a707c1af513c66a1e2')
        self.assertNotEqual(pre_sorted, post_sorted)

    def test_hash_integer(self):
        """
        Test the hashing of an integer.
        """

        data = 1

        self.assertEqual(
            hash_helper.hash_data(data),
            "e25388fde8290dc286a6164fa2d97e551b53498dcbf7bc378eb1f178"
        )

    def test_hash_list(self):
        """
        Test the hashing of a list.
        """

        data = ["DEF", "ABC"]

        self.assertEqual(
            hash_helper.hash_data(data),
            'fd6639af1cc457b72148d78e90df45df4d344ca3b66fa44598148ce4'
        )

    def test_hash_empty_list(self):
        """
        Test the hashing of an empty list.
        """

        data = []

        self.assertEqual(
            hash_helper.hash_data(data),
            'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'
        )

    def test_hash_none(self):
        """
        Test the hashing of None.
        """

        data = None

        self.assertEqual(
            hash_helper.hash_data(data),
            '741e1753b71b2b6b2879a507a69a00f8933bca84317a40e04a011d77'
        )

    def test_hash_list_ordering(self):
        """
        Test the hashing of lists verifying that two lists that are only different in ordering are
        considered the same.
        """

        pre_sorted = hash_helper.hash_data(["DEF", "ABC", 1])
        post_sorted = hash_helper.hash_data([1, "ABC", "DEF"])

        self.assertEqual(pre_sorted, '9fe0831cf1aa981d9781d112a6a87ed102752b16682a0bbb2fda9163')
        self.assertEqual(pre_sorted, post_sorted)

    def test_hash_dictionary_filtered(self):
        """
        Test hashing of a dictionary but with a list of keys that should not be included in the
        hash.
        """

        data = {
            "A": "aaaa",
            "B": "bbbb",
            "One": 1,
            2: "Two",
            "list" : [1, 2, 3, 4]
        }

        self.assertEqual(
            hash_helper.hash_data(data, ["A", 2]),
            "6485bff299355123ad83272c364132c8c5e1641a4026b23af45b7d70"
        )

        # Make sure an ordered dict is handled as a dict
        self.assertEqual(
            hash_helper.hash_data(OrderedDict(data), ["A", 2]),
            "6485bff299355123ad83272c364132c8c5e1641a4026b23af45b7d70"
        )

    def test_hash_dictionary_filtered_in_list(self):
        """
        Test hashing of a dictionary but with a list of keys that should not be included in the
        hash.
        """

        data = {
            "A": "aaaa",
            "dict" : {
                'B' : 'bbbb',
                'C' : 'cccc'
            }
        }

        self.assertEqual(
            hash_helper.hash_data(data, ["B"]),
            "9646b619d3e7ae9951a80aa68d29ddf62205033c6d67b31d625f5b72"
        )

        self.assertEqual(
            hash_helper.hash_data(data, ["C"]),
            "048f88e05df4c32adb4309285c7069c3689228b8d4cf4d7f5f58b26e"
        )


    def test_hash_list_with_one_entry(self):
        """
        Test hashing of a list with a single entry when compared to a non-list with the same value.
        """

        self.assertEqual(
            hash_helper.hash_data(["B"]),
            hash_helper.hash_data("B"),
        )

class TestWebDriverClient(unittest.TestCase):

    def test_add_auth_to_url(self):
        self.assertEqual(WebDriverClient.add_auth_to_url("http://tree.com", "admin", "changeme"), "http://admin:changeme@tree.com")
        self.assertEqual(WebDriverClient.add_auth_to_url("http://tree.com:8888", "admin", "changeme"), "http://admin:changeme@tree.com:8888")

    def test_add_auth_to_url_existing_user_pass(self):
        self.assertEqual(WebDriverClient.add_auth_to_url("http://user:abc1234@tree.com", "admin", "changeme"), "http://admin:changeme@tree.com")

    def test_add_auth_to_url_no_username(self):
        self.assertEqual(WebDriverClient.add_auth_to_url("http://tree.com", None, "changeme"), "http://tree.com")
        self.assertEqual(WebDriverClient.add_auth_to_url("http://tree.com", "", "changeme"), "http://tree.com")

    def test_add_auth_to_url_no_password(self):
        self.assertEqual(WebDriverClient.add_auth_to_url("http://tree.com", "admin", None), "http://tree.com")
        self.assertEqual(WebDriverClient.add_auth_to_url("http://tree.com", "admin", ""), "http://tree.com")

    def test_add_auth_to_url_weird_password(self):
        self.assertEqual(WebDriverClient.add_auth_to_url("http://tree.com", "admin", "/#[zPc"), "http://admin:%2F%23%5BzPc@tree.com")

class TestFormAuthentication(TestWebClient):
    """
    http://lukemurphey.net/issues/758
    """

    def test_form_auth(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_custom_separator", "title", "this is a test")

        data_url = url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/authenticated")
        authentication_url = url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/login")

        web_scraper = WebScraper(timeout=3)
        web_scraper.set_authentication("admin", "changeme", authentication_url, "username", "password")

        results = web_scraper.scrape_page(data_url, selector_field.to_python("h1"), browser=self.BROWSER)
        result = results[0]

        self.assertEqual(len(results), 1)
        self.assertEqual(result['match'][0], "Auth success")

    def test_form_auth_spider(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_custom_separator", "title", "this is a test")

        data_url = url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/authenticated")
        authentication_url = url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/login")

        web_scraper = WebScraper(timeout=3)
        web_scraper.set_authentication("admin", "changeme", authentication_url, "username", "password")

        results = web_scraper.scrape_page(data_url, selector_field.to_python("h1"), page_limit=5, browser=self.BROWSER)

        self.assertEqual(len(results), 4)
        self.assertEqual(results[0]['match'][0], "Auth success")
        self.assertEqual(results[1]['match'][0], "Auth success")
        self.assertEqual(results[2]['match'][0], "Auth success")
        self.assertEqual(results[3]['match'][0], "Auth success")

    def test_detect_form_fields(self):
        client = self.get_client(self.BROWSER)
        _, username_field, password_field = client.detectFormFields("http://127.0.0.1:" + str(self.web_server_port) + "/login")

        self.assertEqual(username_field, 'username')
        self.assertEqual(password_field, 'password')

    def test_detect_form_fields_overlapping_names(self):
        client = self.get_client(self.BROWSER)
        _, username_field, password_field = client.detectFormFields("http://127.0.0.1:" + str(self.web_server_port) + "/login_overlapping_names")

        self.assertEqual(username_field, 'form_userName')
        self.assertEqual(password_field, 'form_userPassword')

    def test_form_auto_discover_form_fields(self):
        client = self.get_client(self.BROWSER)
        client.setCredentials("admin", "changeme")
        client.doFormLogin("http://127.0.0.1:" + str(self.web_server_port) + "/login")

        self.assertEqual(client.is_logged_in, True)
        
    def test_form_fields(self):
        client = self.get_client(self.BROWSER)
        client.setCredentials("admin", "changeme")
        client.doFormLogin("http://127.0.0.1:" + str(self.web_server_port) + "/login", "username", "password")

        self.assertEqual(client.is_logged_in, True)

        content = client.get_url("http://127.0.0.1:" + str(self.web_server_port) + "/authenticated")
        
        client.close()

        self.assertTrue("<h1>Auth success</h1>" in content)

    def test_form_auth_auto_discover_form_fields(self):
        url_field = URLField("test_web_input", "title", "this is a test")
        selector_field = SelectorField("test_custom_separator", "title", "this is a test")

        data_url = url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/authenticated")
        authentication_url = url_field.to_python("http://127.0.0.1:" + str(self.web_server_port) + "/login")

        web_scraper = WebScraper(timeout=3)
        web_scraper.set_authentication("admin", "changeme", authentication_url)

        results = web_scraper.scrape_page(data_url, selector_field.to_python("h1"), browser=self.BROWSER)
        result = results[0]

        self.assertEqual(len(results), 1)
        self.assertEqual(result['match'][0], "Auth success")

class TestFormAuthenticationFirefox(TestFormAuthentication):
    """
    http://lukemurphey.net/issues/1968
    """

    BROWSER = WebScraper.FIREFOX

class TestFormAuthenticationChrome(TestFormAuthentication):
    """
    http://lukemurphey.net/issues/1968
    """

    BROWSER = WebScraper.CHROME

if __name__ == "__main__":

    try:

        report_path = os.path.join('..', os.environ.get('TEST_OUTPUT', 'tmp/test_report.html'))

        # Make the test directory
        try:
            os.makedirs(os.path.dirname(report_path))
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise

        unittest.main()

    finally:
        # Shutdown the server. Note that it should shutdown automatically since it is a daemon
        # thread but this code will ensure it is stopped too.
        UnitTestWithWebServer.shutdownServer()
