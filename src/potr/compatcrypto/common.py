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

# some python3 compatibilty
from __future__ import unicode_literals

import logging
import struct

from potr.utils import human_hash, bytes_to_long, unpack, pack_mpi

DEFAULT_KEYTYPE = 0x0000
pkTypes = {}
def registerkeytype(cls):
    if cls.keyType is None:
        raise TypeError('registered key class needs a type value')
    pkTypes[cls.keyType] = cls
    return cls

def generateDefaultKey():
    return pkTypes[DEFAULT_KEYTYPE].generate()

class PK(object):
    keyType = None

    @classmethod
    def generate(cls):
        raise NotImplementedError

    @classmethod
    def parsePayload(cls, data, private=False):
        raise NotImplementedError

    def sign(self, data):
        raise NotImplementedError
    def verify(self, data):
        raise NotImplementedError
    def fingerprint(self):
        raise NotImplementedError

    def serializePublicKey(self):
        return struct.pack(b'!H', self.keyType) \
                + self.getSerializedPublicPayload()

    def getSerializedPublicPayload(self):
        buf = b''
        for x in self.getPublicPayload():
            buf += pack_mpi(x)
        return buf

    def getPublicPayload(self):
        raise NotImplementedError

    def serializePrivateKey(self):
        return struct.pack(b'!H', self.keyType) \
                + self.getSerializedPrivatePayload()

    def getSerializedPrivatePayload(self):
        buf = b''
        for x in self.getPrivatePayload():
            buf += pack_mpi(x)
        return buf

    def getPrivatePayload(self):
        raise NotImplementedError

    def cfingerprint(self):
        return '{0:040x}'.format(bytes_to_long(self.fingerprint()))

    @classmethod
    def parsePrivateKey(cls, data):
        implCls, data = cls.getImplementation(data)
        logging.debug('Got privkey of type %r', implCls)
        return implCls.parsePayload(data, private=True)

    @classmethod
    def parsePublicKey(cls, data):
        implCls, data = cls.getImplementation(data)
        logging.debug('Got pubkey of type %r', implCls)
        return implCls.parsePayload(data)

    def __str__(self):
        return human_hash(self.cfingerprint())
    def __repr__(self):
        return '<{cls}(fpr=\'{fpr}\')>'.format(
                cls=self.__class__.__name__, fpr=str(self))

    @staticmethod
    def getImplementation(data):
        typeid, data = unpack(b'!H', data)
        cls = pkTypes.get(typeid, None)
        if cls is None:
            raise NotImplementedError('unknown typeid %r' % typeid)
        return cls, data
