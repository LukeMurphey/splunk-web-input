from website_input_app.search_command import SearchCommand
from web_input import WebInput

from splunk.util import normalizeBoolean

class WebScraper(SearchCommand):
    
    def __init__(self, url, selector, username=None, password=None, timeout=30, name_attributes=[], output_matches_as_mv=True, output_matches_as_separate_fields=False, use_element_name=False, page_limit=1, depth_limit=50, url_filter=None, text_separator=" ", include_raw_content=False):
        
        # Save the parameters
        self.params = {
                       "url": url,
                       "selector": selector,
                       "username": username,
                       "password": password,
                       "timeout": timeout,
                       "name_attributes": name_attributes,
                       "output_matches_as_mv": normalizeBoolean(output_matches_as_mv),
                       "output_matches_as_separate_fields": normalizeBoolean(output_matches_as_separate_fields),
                       "include_empty_matches": False,
                       "proxy_type": "http",
                       "proxy_server": None,
                       "proxy_port": None,
                       "proxy_user": None,
                       "proxy_password": None,
                       "use_element_name" : normalizeBoolean(use_element_name),
                       "page_limit" : int(page_limit),
                       "depth_limit" : int(depth_limit),
                       "url_filter" : url_filter,
                       "include_raw_content" : normalizeBoolean(include_raw_content),
                       "text_separator" : text_separator
                       }
        
        SearchCommand.__init__(self, run_in_preview=True, logger_name="web_scrape")
        
        self.logger.info("Web scraper running against url=%s", url)
    
    def handle_results(self, results, in_preview, session_key):
        
        # FYI: we ignore results since this is a generating command
        
        # Do the scraping
        results = WebInput.scrape_page(**self.params)
        
        # Output the results
        self.output_results(results)
        
if __name__ == '__main__':
    WebScraper.execute()