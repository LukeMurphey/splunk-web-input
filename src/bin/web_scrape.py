from website_input_app.search_command import SearchCommand
from web_input import WebInput
import sys

class WebScraper(SearchCommand):
    
    def __init__(self, url, selector, username=None, password=None, timeout=30, name_attributes=[], output_matches_as_mv=True, output_matches_as_separate_fields=False):
        
        # Save the parameters
        self.url = url
        self.selector = selector
        self.username = username
        self.password = password
        self.timeout = timeout
        self.name_attributes = name_attributes
        self.output_matches_as_mv = output_matches_as_mv
        self.output_matches_as_separate_fields = output_matches_as_separate_fields
        
        SearchCommand.__init__(self, run_in_preview=True, logger_name="web_scrape")
        
        self.logger.info("Web scraper running against url=%s", url)
    
    def handle_results(self, results, in_preview, session_key):
        
        # FYI: we ignore results since this is a generating command
        
        # Do the scraping
        result = WebInput.scrape_page(self.url, self.selector, self.username, self.password, self.timeout, self.name_attributes, self.output_matches_as_mv, self.output_matches_as_separate_fields, include_empty_matches=False, proxy_type="http", proxy_server=None, proxy_port=None, proxy_user=None, proxy_password=None)
        
        self.logger.info("Retrieved results, count=%r", result)
        
        # Output the results
        self.output_results([result])
        
if __name__ == '__main__':
    try:
        WebScraper.execute()
        sys.exit(0)
    except Exception as e:
        print e