from website_input_app.search_command import SearchCommand
from web_input import WebInput

from splunk.util import normalizeBoolean

class WebScraper(SearchCommand):
    
    def __init__(self, url, selector, username=None, password=None, timeout=30, name_attributes=[], output_matches_as_mv=True, output_matches_as_separate_fields=False, use_element_name=False, page_limit=1, depth_limit=50, url_filter=None):
        
        # Save the parameters
        self.url = url
        self.selector = selector
        self.username = username
        self.password = password
        self.timeout = timeout
        self.name_attributes = name_attributes
        self.output_matches_as_mv = normalizeBoolean(output_matches_as_mv)
        self.output_matches_as_separate_fields = normalizeBoolean(output_matches_as_separate_fields)
        self.use_element_name = normalizeBoolean(use_element_name)
        self.page_limit = int(page_limit)
        self.depth_limit = int(depth_limit)
        self.url_filter = url_filter
        
        SearchCommand.__init__(self, run_in_preview=True, logger_name="web_scrape")
        
        self.logger.info("Web scraper running against url=%s", url)
    
    def handle_results(self, results, in_preview, session_key):
        
        # FYI: we ignore results since this is a generating command
        
        # Do the scraping
        results = WebInput.scrape_page(self.url, self.selector, self.username, self.password, self.timeout, self.name_attributes, self.output_matches_as_mv, self.output_matches_as_separate_fields, include_empty_matches=False, proxy_type="http", proxy_server=None, proxy_port=None, proxy_user=None, proxy_password=None, use_element_name=self.use_element_name, page_limit=self.page_limit, depth_limit=self.depth_limit, url_filter=self.url_filter)
        
        #self.logger.debug("Retrieved results, result=%r", result)
        
        # Output the results
        self.output_results(results)
        
if __name__ == '__main__':
    WebScraper.execute()