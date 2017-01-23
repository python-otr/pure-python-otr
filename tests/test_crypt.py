# pylint: disable=import-error
# pylint: disable=invalid-name
# pylint: disable=missing-docstring
# pylint: disable=wrong-import-position

from __future__ import unicode_literals

import os
import sys
import unittest

import potr

sys.path.append(os.path.join(os.path.dirname(__file__), 'helpers'))
from potr_test_helpers import to_hex

class CryptTest(unittest.TestCase):

    def test_SHA256HMAC160(self):
        # echo -n 'this is a test' | openssl dgst -sha256 -hmac key | cut -c 1-40
        self.assertEqual(
            to_hex(potr.crypt.SHA256HMAC160(b'key', b'this is a test')),
            b'a85e8284b3aabd90add3da46176bce8e10eff8ea')
