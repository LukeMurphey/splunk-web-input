import hashlib
from collections import OrderedDict

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
        for key, value in sorted(data.items()):

            if ignore_keys is None or key not in ignore_keys:
                update_hash(key, hashlib_data, ignore_keys)
                update_hash(value, hashlib_data, ignore_keys)

    # If the input is a string
    elif isinstance(data, basestring):
        hashlib_data.update(data)

    elif isinstance(data, list) and not isinstance(data, basestring):

        # Sort the list
        data.sort()

        for entry in data:
            update_hash(entry, hashlib_data, ignore_keys)

    else:
        hashlib_data.update(str(data))

    return hashlib_data


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