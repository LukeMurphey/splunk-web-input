"""
This script provides a search command that allows you to perform web-scrapes from the Splunk
command-line.

This wires up the WebInput modular input code to a search command so that you can execute
web-scrape as the search command..
"""

import os
import sys

from splunk.util import normalizeBoolean

from web_input import WebInput
from website_input_app.search_command import SearchCommand
from website_input_app.web_scraper import WebScraper

path_to_mod_input_lib = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modular_input.zip')
if path_to_mod_input_lib not in sys.path:
    sys.path.insert(0, path_to_mod_input_lib)
from modular_input import ModularInput

class WebScraperSearchCommand(SearchCommand):
    """
    The search command takes the arguments provided by the command-line and sends it to the
    modular input functions so that you could you run the input manually.
    """

    def __init__(self, url=None, selector=None, username=None, password=None, timeout=30,
                 name_attributes=None, output_as_mv=True, output_matches_as_mv=None,
                 output_matches_as_separate_fields=False, use_element_name=False, page_limit=1,
                 depth_limit=50, url_filter=None, text_separator=" ", raw_content=False,
                 include_raw_content=None, browser=None, match_prefix=None, user_agent=None,
                 empty_matches=False, empty_value='NULL', authentication_url=None,
                 username_field=None, password_field=None):

        # Note: output_matches_as_mv and include_raw_content are supported for legacy purposes

        # Make sure the required arguments are provided
        if url is None:
            raise ValueError("url argument must be provided")

        if selector is None:
            raise ValueError("selector argument must be provided")

        # Use the older output_matches_as_mv field if included
        if output_matches_as_mv is not None:
            output_as_mv = output_matches_as_mv

        # Decide on whether to include the matches as separate fields if output_as_mv is set
        if normalizeBoolean(output_as_mv):
            output_as_mv = True
            output_matches_as_separate_fields = False
        else:
            output_as_mv = False
            output_matches_as_separate_fields = True

        if name_attributes is None:
            name_attributes = []

        # Make the web scraper instance
        self.web_scraper = WebScraper(int(timeout))
        self.web_scraper.user_agent = user_agent

        # Save the parameters
        self.params = {
            "url": url,
            "selector": selector,
            "name_attributes": name_attributes,
            "output_matches_as_mv": normalizeBoolean(output_as_mv),
            "output_matches_as_separate_fields": normalizeBoolean(output_matches_as_separate_fields),
            "include_empty_matches": empty_matches,
            "empty_value": empty_value,
            "use_element_name" : normalizeBoolean(use_element_name),
            "page_limit" : int(page_limit),
            "depth_limit" : int(depth_limit),
            "url_filter" : url_filter,
            "include_raw_content" : normalizeBoolean(include_raw_content) if include_raw_content is not None else normalizeBoolean(raw_content),
            "text_separator" : text_separator,
            "browser" : browser,
            "match_prefix" : match_prefix
        }

        if username is not None and password is not None:
            self.web_scraper.set_authentication(username, password, authentication_url, username_field, password_field)

        SearchCommand.__init__(self, run_in_preview=True, logger_name="web_scrape")

        self.logger.info("Web scraper running against url=%s", url)

    def handle_results(self, results, session_key, in_preview):

        # FYI: we ignore results since this is a generating command

        # Make sure that URL is using SSL if on Splunk Cloud
        if ModularInput.is_on_cloud(session_key) and not self.params["url"].startswith("https"):
            raise Exception("The URL to scrape must use HTTPS; Splunk Cloud doesn't allow unsecured network access")

        # Make sure that links get extracted if they point to HTTPS sites if on Splunk Cloud
        self.params['https_only'] = ModularInput.is_on_cloud(session_key)

        # Do the scraping
        results = self.web_scraper.scrape_page(**self.params)

        # Output the results
        self.output_results(results)

if __name__ == '__main__':
    WebScraperSearchCommand.execute()
