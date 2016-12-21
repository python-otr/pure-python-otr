# pylint: disable=invalid-name
# pylint: disable=missing-docstring

import codecs

def to_hex(s):
    return codecs.getencoder('hex')(s)[0]
