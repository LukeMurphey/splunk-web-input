import hashlib
from collections import OrderedDict
from six import string_types, binary_type, text_type

def update_hash(data, hashlib_data=None, ignore_keys=None):
    """
    Update the hash data.

    Arguments:
    data -- The data to hash
    hashlib_data -- The existing hash that contains the hash thus far
    ignore_keys -- A list of keys to ignore in the dictionaries
    """

    if hashlib_data is None:
        # Make a hasher capable of handling SHA224
        hashlib_data = hashlib.sha224()

    # Handle the dictionary
    if isinstance(data, dict) or isinstance(data, OrderedDict):

        # Sort the dictionary by key
        for key, value in sorted(data.items(), key=normalize_value):

            if ignore_keys is None or key not in ignore_keys:
                update_hash(key, hashlib_data, ignore_keys)
                update_hash(value, hashlib_data, ignore_keys)

    # If the input is a string
    elif isinstance(data, string_types):
        bin_data = data.encode("utf-8", "replace")
        hashlib_data.update(bin_data)

    # If the input is a binary string
    elif isinstance(data, binary_type):
        hashlib_data.update(data)

    # If is an array
    elif isinstance(data, list) and not isinstance(data, string_types):
        # Sort the list (use a copy so that we don't mess with the original)
        sorted_array = data[:]
        sorted_array.sort(key=normalize_value)

        for entry in sorted_array:
            update_hash(entry, hashlib_data, ignore_keys)

    else:
        hashlib_data.update(normalize_value(data))

    return hashlib_data

def normalize_value(item):
    if isinstance(item, string_types):
        return item.encode("utf-8", "replace")
    elif isinstance(item, binary_type):
        return item.decode("utf-8", "replace")
    else:
        return text_type(item).encode("utf-8", "replace")

def compare(item1, item2):
    # Make sure they are both strings
    if not isinstance(item1, string_types):
        item1 = text_type(item1)
    
    if not isinstance(item2, string_types):
        item2 = text_type(item2)

    if item1 < item2:
        return -1
    elif item1 > item2:
        return 1
    else:
        return 0

def hash_data(data, ignore_keys=None):
    """
    Hash the data and compute a SHA224 hex digest that uniquely represents the data.

    Arguments:
    data -- The data to hash
    ignore_keys -- A list of keys to ignore in the dictionaries
    """

    # Make a hasher capable of handling SHA224
    hashlib_data = hashlib.sha224()

    # Update the hash data accordingly
    update_hash(data, hashlib_data, ignore_keys)

    # Compute the hex result
    return hashlib_data.hexdigest()
