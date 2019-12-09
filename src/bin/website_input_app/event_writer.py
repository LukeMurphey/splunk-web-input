"""
This script creates stash files for indexing data within Splunk.

Here is a sample of using the StashNewWriter to write out data:

from event_writer import StashNewWriter

writer = StashNewWriter(index='summary', source_name='test_of_event_writer')
writer.write_event({'message': 'here is an event'})
"""

from datetime import datetime, timedelta, tzinfo
import time
import random
import re
from splunk.clilib.bundle_paths import make_splunkhome_path

try:
    basestring
except:
    basestring = str

# Python handles datetimes badly, really badly. Below is a UTC timezone implementation since
# Python does not include one by default
TIMEDELTA_ZERO = timedelta(0)

class UTC(tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return TIMEDELTA_ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return TIMEDELTA_ZERO

utc = UTC()

class EventWriter(object):
    """
    The event writer class provides a mechanism for writing out events directly to Splunk.
    """
    # Below is a dictionary that maps special field names to the one that should be used in the
    # summary indexed event. Note: a value of None will prevent the field from being persisted.
    SPECIAL_FIELDS_MAP = {
        "host"          : "orig_host",
        "_raw"          : "orig_raw",
        "source"        : "orig_source",
        "sourcetype"    : "orig_sourcetype",
        "_time"         : "orig_time",
        "index"         : "orig_index",
        "event_id"      : "orig_event_id",
        "splunk_server" : "orig_splunk_server",
        "date_"         : "orig_date",
        "linecount"     : "orig_linecount",

        # Dropped this punct field since has been known to cause Splunk's parsing to fail
        "punct"         : None,
        "tag"           : "orig_tag",
        "eventtype"     : "orig_eventtype",
        "timestartpos"  : "orig_timestartpos",
        "timeendpos"    : "orig_timeendpos"
    }

    def get_basic_fields(self, event):
        """
        Get a list of the fields that must be included in every event. A new dictionary will be
        returned. including the fields that need to be included in the summary event.

        Arguments:
        event -- a Splunk search result
        """

        dictionary = {}

        return dictionary

    def write_event(self, event, is_raw_string=False):
        """
        Writes the provided event (as a dictionary) to a stash file and returns the name of the file
        written.

        Arguments:
        event -- a Splunk search result
        is_raw_string -- indicates if the events should be written as raw strings.
        """

        return self.write_events([event], is_raw_string)

    def write_events(self, array_of_events, is_raw_string=False):
        """
        Writes the provided events (as dictionaries). This function must be implemented by
        sub-classes.

        Arguments:
        array_of_events -- an array of Splunk search results
        is_raw_string -- indicates if the events should be written as raw strings.
        """

        raise NotImplementedError("The write_events function must be implemented by sub-classes \
        of EventWriter")

    def event_to_string(self, result, event_time=None, ignore_empty_fields=True):
        """
        Produces a single line event that represents a single event (for the stash).

        Arguments:
        result -- a Splunk search result
        event_time -- The time of the event (defaults to the current time)
        ignore_empty_fields -- Do not include arguments whose value is empty
        """

        # Populate the event time if not provided
        if event_time is None:
            event_time = datetime.now(utc)

        # Get the timestamp formatted correctly for Splunk (e.g. 05/13/2011 14:35:00)
        date_str = event_time.strftime("%m/%d/%Y %H:%M:%S UTC")

        # Start the event with the date
        event = date_str

        # Get the fields that should be included with every event
        basic_fields = self.get_basic_fields(result)

        # Set the time to the current time
        basic_fields["_time"] = time.mktime(event_time.timetuple())

        for key in basic_fields:
            event = event + ", %s=\"%s\"" % (key, basic_fields[key])

        # Add the event fields
        for key in result:

            # Escape special fields that Splunk will overwrite
            converted_key = self.convert_special_fields(key)

            # Do not include fields whose name is empty or none since this indicates that the field
            # should not be included at all
            if converted_key is None or len(converted_key) == 0:
                pass #Do nothing, this field will be excluded

            # Make sure the field is not an underscore field (these are meta fields that should not
            # be included)
            elif converted_key.startswith("_"):
                pass #Do nothing, this field will be excluded

            # The field has a single value, write it out
            elif not isinstance(result[key], list) or isinstance(result[key], basestring):

                result_value = str(result[key])

                # If the field is blank then do not include it if we are supposed to exclude it
                if len(result_value) <= 0 and ignore_empty_fields == True:
                    pass # Ignore this field and continue to the next field value
                else:
                     #TODO: need to figure out if field names must be escaped
                    event = event + ", %s=\"%s\"" % (converted_key, self.escape_value(result_value))

            # The field name has multiple values, write out multiple key/value pairs accordingly.
            else:
                values = result[key]

                # Add each value as a separate field
                for value in values:

                    value = str(value)

                    # If the field is blank then do not include it if we are supposed to exclude it
                    if len(value) <= 0 and ignore_empty_fields:
                        pass # Ignore this field and continue to the next field value
                    else:
                        event = event + ", %s=\"%s\"" % (converted_key, self.escape_value(value))

        # Return the resulting event
        return event

    def flush(self):
        """
        Some event writers may need to cache the events and send them in one burst (as opposed to
        streaming them).

        This function should be sub-classed by writers that need to send the events at the end of
        a stream.
        """
        pass

    def escape_value(self, value):
        """
        Escapes the given value such that any quotes within the value will not cause the even to be
        parsed incorrectly.

        Arguments:
        value -- The string value to be escaped
        """
        return value.replace('\\', '\\\\').replace('"', '\\"')

    def convert_special_fields(self, name):
        """
        Convert the field to one that can be persisted. This is necessary because some fields
        (like _raw, host) are special fields that cannot be summary indexed without conflicting
        with a native Splunk field.

        Arguments:
        name -- field name to convert
        """

        # If the field is a special field, then change the name
        try:
            # Convert the old tag fields
            if name.startswith("tag::"):
                return "orig_" + name
            elif name.startswith("date_"):
                return None
            else:
                return self.SPECIAL_FIELDS_MAP[name]
        except KeyError:
            # The field was not found. This indicates that it does not need to be converted so
            # return the original.
            return name

class StashNewWriter(EventWriter):
    """
    The Stash writer class provides a mechanism for writing out events that will be processed by
    Splunk as stash events (and summary indexed accordingly).
    """

    # This is the line-breaker for stash new
    LINE_BREAKER = "==##~~##~~  1E8N3D4E6V5E7N2T9 ~~##~~##=="

    # Below is a sample of stash new file:
    """
    ***SPLUNK*** index=summary source="Some Search"
    ==##~~##~~  1E8N3D4E6V5E7N2T9 ~~##~~##==
    05/13/2011 14:35:00, search_name="Some Search", search_now=1305315300.000,severity="high"
    ==##~~##~~  1E8N3D4E6V5E7N2T9 ~~##~~##==
    """

    def __init__(self, index, source_name, file_extension=".stash_new", sourcetype=None, host=None):
        """
        Constructor for the stash writer,=.

        Arguments:
        index -- the index to send the events to
        source_name -- the search that is being used to generate the results
        file_extension -- the extension of the stash file (usually .stash_new)
        sourcetype -- the sourcetype to use for the event
        host -- the host to assign the event to
        """
        self.index = index
        self.source_name = source_name
        self.file_extension = file_extension
        self.sourcetype = sourcetype
        self.host = host

    def make_fields_list(self, fields_dict):
        """
        Make a string with the list of fields in KV format.
        """

        fields_str = None

        for field_name, field_value in fields_dict.items():

            # Populate the field string if it is empty
            if fields_str is None:
                fields_str = ''

            # Add the spacer if necessary
            elif fields_str is not None:
                fields_str += ' '

            # Add the field
            fields_str += field_name + '="' + field_value + '"'

        return fields_str

    def get_header(self):
        """
        Provides a header for the stash file which defines the index and the source for the event.
        """

        fields_dict = {
            'index' : self.index
        }

        # Make sure the source is defined
        if self.source_name is None:
            fields_dict['source'] = 'undefined'
        else:
            fields_dict['source'] = self.source_name

        # Add the host if it is defined
        if self.host is not None:
            fields_dict['host'] = self.host

        return "***SPLUNK*** " + self.make_fields_list(fields_dict) + '"\r\n'

    def get_file_name(self):
        "Get a file name that can be used for creating a stash file"

        # Sanitize the source name
        source_name = re.sub(r"[^a-zA-Z_0-9]", "_", str(self.source_name))

        # Make the file path
        stash_file = make_splunkhome_path(["var", "spool", "splunk", source_name + "_" \
        + str(time.time()) + "_" + str(random.randrange(0, 65535, 1)) + self.file_extension])

        return stash_file

    def write_events(self, array_of_events, is_raw_string=False):
        """
        Writes the provided events (as dictionaries) to a stash file and returns the name of the
        file written.

        Arguments:
        array_of_events -- an array of Splunk search results
        is_raw_string -- indicates if the events should be written as raw strings
        """

        # Open the stash file
        stash_file = self.get_file_name()
        stash_file_h = open(stash_file, 'a')

        # Write the header
        stash_file_h.write(self.get_header())

        # Write the line_breaker
        stash_file_h.write(self.LINE_BREAKER)
        stash_file_h.write("\n")

        if self.sourcetype is not None:
            stash_file_h.write('sourcetype=\"' + self.sourcetype + '\"')

        # Write out the events
        for event in array_of_events:

            if is_raw_string:
                stash_file_h.write(event)
            else:
                stash_file_h.write(self.event_to_string(event))

            stash_file_h.write("\n")

        # Close the file
        stash_file_h.close()

        # Return the file name.
        return stash_file

class CachedWriter(EventWriter):
    """
    Stores the events in an variable so that they can be programmatically returned (useful for
    testing purposes).The results will be stored in the variable "stored_events".
    """

    def __init__(self, escape_fields=False):
        """
        Initializes the cached writer.

        Arguments:
        escape_fields -- indicates whether the field names should be converted
        """

        self.stored_events = []
        self.escape_fields = escape_fields

    def write_events(self, array_of_events, is_raw_string=False):
        """
        Writes the provided events (as dictionaries) to the list of stored events.

        Arguments:
        array_of_events -- an array of Splunk search results
        is_raw_string -- indicates if the events should be written as raw strings
        """

        # Convert the field names if requested
        if self.escape_fields:

            # Convert the field name for each event
            for event in array_of_events:

                # This will be the new event created
                new_event = {}

                if is_raw_string:
                    new_event['_raw'] = event

                else:
                    # Convert each field name and append it
                    for key, value in event.items():

                        # Convert the name
                        key = self.convert_special_fields(key)

                        # Add the field
                        new_event[key] = value

                # Add the converted event
                self.stored_events.append(new_event)

        # If no conversion is needed then just store the event
        else:
            self.stored_events.extend(array_of_events)
