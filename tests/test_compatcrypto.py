# pylint: disable=invalid-name
# pylint: disable=missing-docstring

from __future__ import unicode_literals

import codecs
import unittest

import potr

def to_hex(s):
    return codecs.getencoder('hex')(s)[0]

class CompatCryptoTest(unittest.TestCase):

    def test_SHA256(self):
        # echo -n 'this is a test' | shasum -a 256
        self.assertEqual(
            to_hex(potr.compatcrypto.SHA256('this is a test')),
            '2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c')

    def test_SHA1(self):
        # echo -n 'this is a test' | shasum
        self.assertEqual(
            to_hex(potr.compatcrypto.SHA1('this is a test')),
            'fa26be19de6bff93f70bc2308434e4a440bbad02')

    def test_SHA1HMAC(self):
        # echo -n 'this is a test' | openssl dgst -sha1 -hmac key
        self.assertEqual(
            to_hex(potr.compatcrypto.SHA1HMAC(b'key', 'this is a test')),
            '778d71b5ef5a446b2c1c39d1f289ede37bb4ba2e')

    def test_SHA256HMAC(self):
        # echo -n 'this is a test' | openssl dgst -sha56 -hmac key
        self.assertEqual(
            to_hex(potr.compatcrypto.SHA256HMAC(b'key', 'this is a test')),
            'a85e8284b3aabd90add3da46176bce8e10eff8eafd7d096d8ba7d9396623b894')

    def test_SHA256HMAC160(self):
        # echo -n 'this is a test' | openssl dgst -sha256 -hmac key | cut -c 1-40
        self.assertEqual(
            to_hex(potr.compatcrypto.SHA256HMAC160(b'key', 'this is a test')),
            'a85e8284b3aabd90add3da46176bce8e10eff8ea')
