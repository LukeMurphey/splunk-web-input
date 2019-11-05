"""
This module provides the classes for providing an input that does web-scraping in Splunk.

The classes included are:

  * WebsiteInputConfig: a class for getting information from Splunk for configuration of the app
  * WebInput: the main modular input class
"""
import logging
from logging import handlers
import sys
import os
import hashlib
import re
import splunk

path_to_mod_input_lib = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modular_input.zip')
if path_to_mod_input_lib not in sys.path:
    sys.path.insert(0, path_to_mod_input_lib)
from modular_input import Field, ListField, FieldValidationException, ModularInput, URLField, DurationField, BooleanField, IntegerField, StaticListField
from modular_input.shortcuts import forgive_splunkd_outages
from modular_input.secure_password import get_secure_password

from website_input_app.timer import Timer
from website_input_app.web_client import LoginFormNotFound, FormAuthenticationFailed, WebClientException
from website_input_app.web_scraper import WebScraper
from website_input_app.selector_field import SelectorField
from website_input_app.event_writer import StashNewWriter
from website_input_app import hash_helper

from splunk.models.base import SplunkAppObjModel
from splunk.models.field import Field as ModelField
from splunk.models.field import IntField as ModelIntField

# from __builtin__ import classmethod

class WebsiteInputConfig(SplunkAppObjModel):

    resource = '/admin/app_website_input'
    proxy_server = ModelField()
    proxy_port = ModelIntField()
    proxy_type = ModelField()
    proxy_user = ModelField()
    proxy_password = ModelField()

class WebInputResult():
    """
    An object representing the output of the web input modular input call ot output_results().
    """

    def __init__(self):
        self.match_hashes = []
        self.result_hashes = []

        self.latest_content_hash = None
        self.latest_matches_hash = None

        self.results_outputted = 0

    def get_hash_of_all_matches(self):
        return hash_helper.hash_data(self.match_hashes)

    def get_hash_of_all_results(self):
        return hash_helper.hash_data(self.result_hashes)

class WebInput(ModularInput):
    """
    The web input modular input connects to a web-page obtains information from it.
    """

    OUTPUT_USING_STASH = True

    # Static variables for when to output results
    OUTPUT_RESULTS_ALWAYS = 'always'
    OUTPUT_RESULTS_WHEN_MATCHES_CHANGE = 'when_matches_change'
    OUTPUT_RESULTS_WHEN_CONTENTS_CHANGE = 'when_contents_change'

    OUTPUT_RESULTS_OPTIONS = [OUTPUT_RESULTS_ALWAYS, OUTPUT_RESULTS_WHEN_MATCHES_CHANGE, OUTPUT_RESULTS_WHEN_CONTENTS_CHANGE]

    # The following define which secure password entry to use for the proxy
    PROXY_PASSWORD_REALM = 'website_input_app_proxy'
    PROXY_PASSWORD_USERNAME = 'IN_CONF_FILE'

    def __init__(self, timeout=30, **kwargs):

        scheme_args = {'title': "Web-pages",
                       'description': "Retrieve information from web-pages",
                       'use_external_validation': "true",
                       'streaming_mode': "xml",
                       'use_single_instance': "true"}

        args = [
            Field("title", "Title", "A short description (typically just the domain name)", empty_allowed=False),
            URLField("url", "URL", "The URL to connect to (must be be either HTTP or HTTPS protocol)", empty_allowed=False, require_https_on_cloud=True),
            DurationField("interval", "Interval", "The interval defining how often to perform the check; can include time units (e.g. 15m for 15 minutes, 8h for 8 hours)", empty_allowed=False),
            IntegerField("timeout", "Timeout", 'The timeout (in number of seconds)', none_allowed=True, empty_allowed=True),
            SelectorField("selector", "Selector", "A selector that will match the data you want to retrieve", none_allowed=True, empty_allowed=True),

            # HTTP client options
            Field("user_agent", "User Agent", "The user-agent to use when communicating with the server", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("browser", "Browser", 'The browser to use', none_allowed=True, empty_allowed=True),

            # Output options
            ListField("name_attributes", "Field Name Attributes", "A list of attributes to use for assigning a field name", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            BooleanField("use_element_name", "Use Element Name as Field Name", "Use the element's tag name as the field name", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            BooleanField("output_as_mv", "Output as Multi-value Field", "Output the matches as multi-value field", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            StaticListField("output_results", "Indicates when results output should be created", "Output the matches only when results changed", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False, valid_values=WebInput.OUTPUT_RESULTS_OPTIONS),
            BooleanField("raw_content", "Raw content", "Return the raw content returned by the server", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            BooleanField("empty_matches", "Empty matches", "Include empty rows (otherwise, they are excluded)", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("text_separator", "Text Separator", 'A string that will be placed between the extracted values (e.g. a separator of ":" for a match against "<a>tree</a><a>frog</a>" would return "tree:frog")', none_allowed=True, empty_allowed=True),

            # Spidering options
            IntegerField("page_limit", "Discovered page limit", "A limit on the number of pages that will be auto-discovered", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            IntegerField("depth_limit", "Depth limit", "A limit on how many levels deep the search for pages will go", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("url_filter", "URL Filter", "A wild-card that will indicate which pages it should search for matches in", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),

            # Authentication options
            Field("username", "Username", "The username to use for authenticating", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("password", "Password", "The password to use for authenticating", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("username_field", "Username field", "The name of the username field on the login form", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            Field("password_field", "Password field", "The name of the password field on the login form", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False),
            URLField("authentication_url", "Authentication URL", "The URL of the login form", none_allowed=True, empty_allowed=True, required_on_create=False, required_on_edit=False, require_https_on_cloud=True)
        ]

        ModularInput.__init__(self, scheme_args, args, logger_name='web_input_modular_input', logger_level=logging.INFO)

        if timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 30

    @classmethod
    def get_file_path(cls, checkpoint_dir, stanza):
        """
        Get the path to the checkpoint file.

        Arguments:
        checkpoint_dir -- The directory where checkpoints ought to be saved
        stanza -- The stanza of the input being used
        """

        return os.path.join(checkpoint_dir, hashlib.md5(stanza.encode('utf-8')).hexdigest() + ".json")

    @forgive_splunkd_outages
    def get_proxy_config(self, session_key, stanza="default"):
        """
        Get the proxy configuration

        Arguments:
        session_key -- The session key to use when connecting to the REST API
        stanza -- The stanza to get the proxy information from (defaults to "default")
        """

        # Don't allow the use of a proxy server on Splunk Cloud since this could
        # allow unencrypted communication. Cloud shouldn't need the use of a proxy anyways.
        if self.is_on_cloud(session_key):
            return "http", None, None, None, None

        # If the stanza is empty, then just use the default
        if stanza is None or stanza.strip() == "":
            stanza = "default"

        # Get the proxy configuration
        try:
            website_input_config = WebsiteInputConfig.get(WebsiteInputConfig.build_id( stanza, "website_input", "nobody"), sessionKey=session_key)

            self.logger.debug("Proxy information loaded, stanza=%s", stanza)

        except splunk.ResourceNotFound:
            self.logger.error('Unable to find the proxy configuration for the specified configuration stanza=%s, error="not found"', stanza)
            raise
        except splunk.SplunkdConnectionException:
            self.logger.error('Unable to find the proxy configuration for the specified configuration stanza=%s error="splunkd connection error"', stanza)
            raise

        # Get the proxy password from secure storage (if it exists)
        secure_password = get_secure_password(realm=WebInput.PROXY_PASSWORD_REALM,
                                              username=WebInput.PROXY_PASSWORD_USERNAME,
                                              session_key=session_key)

        if secure_password is not None:
            proxy_password = secure_password['content']['clear_password']
            self.logger.debug("Loaded the proxy password from secure storage")
        else:
            proxy_password = website_input_config.proxy_password

        return website_input_config.proxy_type, website_input_config.proxy_server, website_input_config.proxy_port, website_input_config.proxy_user, proxy_password

    def output_results(self, results, index, source, sourcetype, host, checkpoint_data, output_results_policy, result_info = None):
        """
        Output the results to Splunk unless the results don't match the export policy.

        Returns an integer indicating how many results were outputted.

        Arguments:
        results -- The results from scrape_page (a list of dictionaries containing the matches and related data)
        index -- The index to send the data to
        source -- The name of the source
        sourcetype -- The name of the sourcetype
        host -- The name of the host
        checkpoint_data -- The checkpoint data dictionary provided to the modular input
        output_results_policy -- A string representing how output should be exported
        result_info -- An instance of WebInputResult for tracking information such as result hashes
        """

        # Create an instance of the web-result output
        if result_info is None: 
            result_info = WebInputResult()

        # Process the result (if we got one)
        if results is not None:

            # Compute the hash of the matches
            with Timer() as timer:

                # Hash the results
                result_info.latest_content_hash = hash_helper.hash_data(results, WebScraper.GENERATED_FIELDS)

                # Accumulate the matches hashes so that we can generate a hash of the matches
                matches_content = []

                for result in results:
                    # Handle MV based match content
                    if 'match' in result:
                        matches_content.append(result['match'])

                    # Handle non-MV based match content by looking for fields that are not generated as meta fields
                    else:
                        for key, value in result.items():
                            if key not in WebScraper.GENERATED_FIELDS:
                                matches_content.append(value)

                result_info.latest_matches_hash = hash_helper.hash_data(matches_content)

            # Add to the list of the matches
            result_info.match_hashes.append(result_info.latest_matches_hash)

            # Calculate the hash of all of the matches
            hash_of_all_matches = result_info.get_hash_of_all_matches()
            self.logger.debug("Hash of results calculated, time=%sms, hash=%s, prior_hash=%s", round(timer.msecs, 3), hash_of_all_matches, checkpoint_data.get('matches_hash', ''))

            # Don't output the results if we are set to not output results unless the matches change
            # Note: we will compare the content later
            if output_results_policy == WebInput.OUTPUT_RESULTS_WHEN_MATCHES_CHANGE and checkpoint_data.get('matches_hash', '') == hash_of_all_matches:
                self.logger.info("Matches data matched the prior result, it will be skipped since output_results=%s, hash=%s", output_results_policy, hash_of_all_matches)

            else:
                # Build up a list of the hashes so that we can determine if the content changed
                for r in results:

                    # Add the hash
                    if r.get('content_sha224', None) != None:
                        result_info.result_hashes.append(r.get('content_sha224', ''))

                # Check to see if the content changed
                # Don't output the results if we are set to not output results unless the content changes
                hash_of_all_results = result_info.get_hash_of_all_results()
                if output_results_policy == WebInput.OUTPUT_RESULTS_WHEN_CONTENTS_CHANGE and checkpoint_data.get('content_hash', '') == hash_of_all_results:
                    self.logger.info("Content data matched the prior result, it will be skipped since output_results=%s, hash=%s", output_results_policy, hash_of_all_results)

                else:
                    # Process each event
                    for r in results:
                        # Send the event
                        if self.OUTPUT_USING_STASH:
                            # Write the event as a stash new file
                            writer = StashNewWriter(index=index, source_name=source, file_extension=".stash_web_input", sourcetype=sourcetype, host=host)
                            self.logger.debug("Wrote stash file=%s", writer.write_event(r))

                        else:
                            # Write the event using the built-in modular input method
                            self.output_event(r, source, index=index, source=source, sourcetype=sourcetype, host=host, unbroken=True, close=True, encapsulate_value_in_double_quotes=True)

                        # Keep a count of the results sent
                        result_info.results_outputted += 1

        return result_info

    def run(self, stanza, cleaned_params, input_config):

        # Make the parameters
        interval              = cleaned_params["interval"]
        title                 = cleaned_params["title"]
        url                   = cleaned_params["url"]
        selector              = cleaned_params.get("selector", None)
        username              = cleaned_params.get("username", None)
        password              = cleaned_params.get("password", None)
        name_attributes       = cleaned_params.get("name_attributes", [])
        user_agent            = cleaned_params.get("user_agent", None)
        timeout               = cleaned_params.get("timeout", self.timeout)
        sourcetype            = cleaned_params.get("sourcetype", "web_input")
        host                  = cleaned_params.get("host", None)
        index                 = cleaned_params.get("index", "default")
        conf_stanza           = cleaned_params.get("configuration", None)
        use_element_name      = cleaned_params.get("use_element_name", False)
        page_limit            = cleaned_params.get("page_limit", 1)
        url_filter            = cleaned_params.get("url_filter", None)
        depth_limit           = cleaned_params.get("depth_limit", 25)
        raw_content           = cleaned_params.get("raw_content", False)
        text_separator        = cleaned_params.get("text_separator", " ")
        browser               = cleaned_params.get("browser", WebScraper.INTEGRATED_CLIENT)
        output_as_mv          = cleaned_params.get("output_as_mv", True)
        output_results_policy = cleaned_params.get("output_results", None)
        username_field        = cleaned_params.get("username_field", None)
        password_field        = cleaned_params.get("password_field", None)
        authentication_url    = cleaned_params.get("authentication_url", None)
        source                = stanza

        if self.needs_another_run(input_config.checkpoint_dir, stanza, interval):

            # Don't scan the URL if the URL is unencrypted and the host is on Cloud
            if self.is_on_cloud(input_config.session_key) and not url.scheme == "https":
                self.logger.warn("The URL will not be processed because the host is running on Splunk Cloud and the URL isn't using encryption, url=%s", url.geturl())
                return

            # Don't scan the URL if the login URL is unencrypted and the host is on Cloud
            if self.is_on_cloud(input_config.session_key) and authentication_url is not None and authentication_url.scheme != "https":
                self.logger.warn("The URL will not be processed because the host is running on Splunk Cloud and the login URL isn't using encryption, authentication_url=%s", authentication_url.geturl())
                return

            # Get the proxy configuration
            try:
                proxy_type, proxy_server, proxy_port, proxy_user, proxy_password = self.get_proxy_config(input_config.session_key, conf_stanza)
            except splunk.ResourceNotFound:
                self.logger.error("The proxy configuration could not be loaded (resource not found). The execution will be skipped for now for this input with stanza=%s", stanza)
                return
            except splunk.SplunkdConnectionException:
                self.logger.error("The proxy configuration could not be loaded (splunkd connection problem). The execution will be skipped for now for this input with stanza=%s", stanza)
                return

            # Get the secure password if necessary
            if username is not None:
                secure_password = get_secure_password(realm=stanza, session_key=input_config.session_key, logger=self.logger)

                if secure_password is not None:
                    password = secure_password['content']['clear_password']
                    self.logger.debug("Successfully loaded the secure password for input=%s", stanza)

            # Get the information from the page
            try:

                # Make sure the page_limit is not too small
                if page_limit < 1 or page_limit is None or page_limit == "":
                    self.logger.warn("The parameter is too small for page_limit=%r", page_limit)
                    page_limit = 1

                # Make sure the depth_limit is valid
                if depth_limit < 1 or depth_limit is None or depth_limit == "":
                    self.logger.warn("The parameter is too small for depth_limit=%r", depth_limit)
                    depth_limit = 50
    
                # Determine how to make the match fields
                output_matches_as_mv = True
                output_matches_as_separate_fields = False

                if not output_as_mv:
                    output_matches_as_mv = False
                    output_matches_as_separate_fields = True

                additional_fields = {
                    'title' : title
                }

                # Make an instance of the web-scraper and initialize it
                web_scraper = WebScraper(timeout, logger=self.logger)

                web_scraper.set_proxy(proxy_type, proxy_server, proxy_port, proxy_user, proxy_password)
                web_scraper.user_agent = user_agent
                web_scraper.set_authentication(username, password, authentication_url, username_field, password_field)

                # Get the checkpoint data so that we can determine the prior hash of the results if necessary
                checkpoint_data = self.get_checkpoint_data(input_config.checkpoint_dir, stanza)

                if checkpoint_data is None:
                    checkpoint_data = {}

                # Keep a list of the matches so that we can determine if any of results changed
                result_info = WebInputResult()

                if output_results_policy == WebInput.OUTPUT_RESULTS_WHEN_CONTENTS_CHANGE or output_results_policy == WebInput.OUTPUT_RESULTS_WHEN_MATCHES_CHANGE:
                    output_fx = None
                else:
                    # Setup the output function so that we can stream the results
                    output_fx = lambda result: self.output_results([result], index, source, sourcetype, host, checkpoint_data, None, result_info)

                # Perform the scrape
                results = web_scraper.scrape_page(url, selector, name_attributes,
                                                 use_element_name=use_element_name,
                                                 page_limit=page_limit,
                                                 depth_limit=depth_limit, url_filter=url_filter,
                                                 include_raw_content=raw_content,
                                                 text_separator=text_separator,
                                                 browser=browser,
                                                 output_matches_as_mv=output_matches_as_mv,
                                                 output_matches_as_separate_fields=output_matches_as_separate_fields,
                                                 additional_fields=additional_fields,
                                                 https_only=self.is_on_cloud(input_config.session_key),
                                                 output_fx=output_fx)

                # Determine the number of results
                if output_fx is None: 
                    matches = len(results)
                elif output_fx is not None:
                    matches = results

                self.logger.info("Successfully executed the website input, matches_count=%r, stanza=%s, url=%s", matches, stanza, url.geturl())
                    
            except LoginFormNotFound as e:
                self.logger.warn('Form authentication failed since the form could not be found, stanza=%s', stanza)

            except FormAuthenticationFailed as e:
                self.logger.warn('Form authentication failed, stanza=%s, error="%s"', stanza, str(e))

            except WebClientException as e:
                self.logger.warn('Client connection failed, stanza=%s, error="%s"', stanza, str(e))

            except Exception:
                self.logger.exception("An exception occurred when attempting to retrieve information from the web-page, stanza=%s", stanza)

            # Get the time that the input last ran
            last_ran = self.last_ran(input_config.checkpoint_dir, stanza)

            # If we didn't output the results already (using streaming output, then do it now)
            if output_fx is None:
                self.output_results(results, index, source, sourcetype, host, checkpoint_data, output_results_policy, result_info)

            # Make the new checkpoint data dictionary
            new_checkpoint_data = {
                'last_run' : self.get_non_deviated_last_run(last_ran, interval, stanza),
                'matches_hash' : result_info.get_hash_of_all_matches(),
                'content_hash' : result_info.get_hash_of_all_results()
            }

            # Save the checkpoint so that we remember when we last executed this
            self.save_checkpoint_data(input_config.checkpoint_dir, stanza, new_checkpoint_data)

            # Force garbage collection at the end of the run
            # This is useful since inputs often time run infrequently and we want to clean up
            # after ourselves while we wait for the next run 
            import gc
            gc.collect()

web_input = None

if __name__ == '__main__':
    try:
        web_input = WebInput()
        web_input.execute()
        sys.exit(0)
    except Exception:
        if web_input is not None:
            web_input.logger.exception("Unhandled exception was caught, this may be due to a defect in the script") # This logs general exceptions that would have been unhandled otherwise (such as coding errors)
        raise
