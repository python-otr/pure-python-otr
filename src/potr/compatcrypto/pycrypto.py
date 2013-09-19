#    Copyright 2012 Kjell Braden <afflux@pentabarf.de>
#
#    This file is part of the python-potr library.
#
#    python-potr is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    any later version.
#
#    python-potr is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this library.  If not, see <http://www.gnu.org/licenses/>.

from Crypto import Cipher
from Crypto.Hash import SHA256 as _SHA256
from Crypto.Hash import SHA as _SHA1
from Crypto.Hash import HMAC as _HMAC
from Crypto.PublicKey import DSA
from Crypto.Random import random
from numbers import Number

from potr.compatcrypto import common
from potr.utils import read_mpi, bytes_to_long, long_to_bytes

def SHA256(data):
    return _SHA256.new(data).digest()

def SHA1(data):
    return _SHA1.new(data).digest()

def HMAC(key, data, mod):
    return _HMAC.new(key, msg=data, digestmod=mod).digest()

def SHA1HMAC(key, data):
    return HMAC(key, data, _SHA1)

def SHA256HMAC(key, data):
    return HMAC(key, data, _SHA256)

def SHA256HMAC160(key, data):
    return SHA256HMAC(key, data)[:20]

def AESCTR(key, counter=0):
    if isinstance(counter, Number):
        counter = Counter(counter)
    if not isinstance(counter, Counter):
        raise TypeError
    return Cipher.AES.new(key, Cipher.AES.MODE_CTR, counter=counter)

class Counter(object):
    def __init__(self, prefix):
        self.prefix = prefix
        self.val = 0

    def inc(self):
        self.prefix += 1
        self.val = 0

    def __setattr__(self, attr, val):
        if attr == 'prefix':
            self.val = 0
        super(Counter, self).__setattr__(attr, val)

    def __repr__(self):
        return '<Counter(p={p!r},v={v!r})>'.format(p=self.prefix, v=self.val)

    def byteprefix(self):
        return long_to_bytes(self.prefix, 8)

    def __call__(self):
        bytesuffix = long_to_bytes(self.val, 8)
        self.val += 1
        return self.byteprefix() + bytesuffix

@common.registerkeytype
class DSAKey(common.PK):
    keyType = 0x0000

    def __init__(self, key=None, private=False):
        self.priv = self.pub = None

        if not isinstance(key, tuple):
            raise TypeError('4/5-tuple required for key')

        if len(key) == 5 and private:
            self.priv = DSA.construct(key)
            self.pub = self.priv.publickey()
        elif len(key) == 4 and not private:
            self.pub = DSA.construct(key)
        else:
            raise TypeError('wrong number of arguments for ' \
                    'private={0!r}: got {1} '
                    .format(private, len(key)))

    def getPublicPayload(self):
        return (self.pub.p, self.pub.q, self.pub.g, self.pub.y)

    def getPrivatePayload(self):
        return (self.priv.p, self.priv.q, self.priv.g, self.priv.y, self.priv.x)

    def fingerprint(self):
        return SHA1(self.getSerializedPublicPayload())

    def sign(self, data):
        # 2 <= K <= q
        K = random.randrange(2, self.priv.q)
        r, s = self.priv.sign(data, K)
        return long_to_bytes(r, 20) + long_to_bytes(s, 20)

    def verify(self, data, sig):
        r, s = bytes_to_long(sig[:20]), bytes_to_long(sig[20:])
        return self.pub.verify(data, (r, s))

    def __hash__(self):
        return bytes_to_long(self.fingerprint())

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.fingerprint() == other.fingerprint()

    def __ne__(self, other):
        return not (self == other)

    @classmethod
    def generate(cls):
        privkey = DSA.generate(1024)
        return cls((privkey.key.y, privkey.key.g, privkey.key.p, privkey.key.q,
                privkey.key.x), private=True)

    @classmethod
    def parsePayload(cls, data, private=False):
        p, data = read_mpi(data)
        q, data = read_mpi(data)
        g, data = read_mpi(data)
        y, data = read_mpi(data)
        if private:
            x, data = read_mpi(data)
            return cls((y, g, p, q, x), private=True), data
        return cls((y, g, p, q), private=False), data
