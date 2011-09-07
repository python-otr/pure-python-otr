#!/usr/bin/env python
#    Copyright 2011 Kjell Braden <afflux@pentabarf.de>
#
#    This file is part of the python-potr library.
#
#    python-potr is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    (at your option) any later version.
#
#    python-potr is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this library.  If not, see <http://www.gnu.org/licenses/>.
import base64
import logging
import struct
from Crypto.Util.number import bytes_to_long, long_to_bytes

OTRTAG = '?OTR'
MESSAGE_TAG_BASE = ' \t  \t\t\t\t \t \t \t  '
MESSAGE_TAG_V1 = ' \t \t  \t '
MESSAGE_TAG_V2 = '  \t\t  \t '

MSGTYPE_NOTOTR = 0
MSGTYPE_TAGGEDPLAINTEXT = 1
MSGTYPE_QUERY = 2
MSGTYPE_DH_COMMIT = 3
MSGTYPE_DH_KEY = 4
MSGTYPE_REVEALSIG = 5
MSGTYPE_SIGNATURE = 6
MSGTYPE_V1_KEYEXCH = 7
MSGTYPE_DATA = 8
MSGTYPE_ERROR = 9
MSGTYPE_UNKNOWN = -1

MSGFLAGS_IGNORE_UNREADABLE = 1

tlvClasses = {}
messageClasses = {}

def registermessage(cls):
    if not hasattr(cls, 'parsePayload'):
        raise TypeError('registered message types need parsePayload()')
    messageClasses[cls.version, cls.msgtype] = cls
    return cls

def registertlv(cls):
    if not hasattr(cls, 'parsePayload'):
        raise TypeError('registered tlv types need parsePayload()')
    tlvClasses[cls.typ] = cls
    return cls

class OTRMessage(object):
    __slots__ = ['payload']
    version = 0x0002
    msgtype = 0
    def __init__(self, payload):
        self.payload = payload

    def getPayload(self):
        return self.payload

    def __str__(self):
        data = struct.pack('!HB', self.version, self.msgtype) \
                + self.getPayload()
        return '?OTR:%s.' % base64.b64encode(data)


class Error(OTRMessage):
    __slots__ = ['error']
    def __init__(self, error):
        self.error = error

    def __repr__(self):
        return '<proto.Error(%r)>' % self.error

    def __str__(self):
        return '?OTR Error:%s' % self.error

class Query(OTRMessage):
    __slots__ = ['v1', 'v2']
    def __init__(self, v1, v2):
        self.v1 = v1
        self.v2 = v2

    @classmethod
    def parse(cls, data):
        v2 = False
        v1 = False
        if len(data) > 0 and data[0] == '?':
            data = data[1:]
            v1 = True

        if len(data) > 0 and data[0] == 'v':
            for c in data[1:]:
                if c == '2':
                    v2 = True
        return cls(v1, v2)

    def __repr__(self):
        return '<proto.Query(v1=%r,v2=%r)>'%(self.v1,self.v2)

    def __str__(self):
        d = '?OTR'
        if self.v1:
            d += '?'
        d += 'v'
        if self.v2:
            d += '2'
        d += '?'
        return d

class TaggedPlaintext(Query):
    __slots__ = ['msg']
    def __init__(self, msg, v1, v2):
        self.msg = msg
        self.v1 = v1
        self.v2 = v2

    def __str__(self):
        data = self.msg + MESSAGE_TAG_BASE
        if self.v1:
            data += MESSAGE_TAG_V1
        if self.v2:
            data += MESSAGE_TAG_V2
        return data

    def __repr__(self):
        return '<proto.TaggedPlaintext(v1={v1!r},v2={v2!r},msg={msg!r})>' \
                .format(v1=self.v1, v2=self.v2, msg=self.msg)

    @classmethod
    def parse(cls, data):
        tagPos = data.find(MESSAGE_TAG_BASE)
        if tagPos < 0:
            raise TypeError(
                    'this is not a tagged plaintext ({0.20!r})'.format(data))

        v1 = False
        v2 = False

        tags = [ data[i:i+8] for i in range(tagPos, len(data), 8) ]
        for tag in tags:
            if not tag.isspace():
                break
            v1 |= tag == MESSAGE_TAG_V1
            v2 |= tag == MESSAGE_TAG_V2

        return TaggedPlaintext(data[:tagPos], v1, v2)

class GenericOTRMessage(OTRMessage):
    __slots__ = ['data']
    def __init__(self, *args):
        if len(args) != len(self.fields):
            raise TypeError('%s needs %d arguments, got %d' %
                    (self.__class__.__name__, len(self.fields), len(args)))

        super(GenericOTRMessage, self).__setattr__('data',
                dict(zip((f[0] for f in self.fields), args)))

    def __getattr__(self, attr):
        if attr in self.data:
            return self.data[attr]
        raise AttributeError(
                "'{t!r}' object has no attribute '{attr!r}'".format(attr=attr,
                t=self.__class__.__name__))

    def __setattr__(self, attr, val):
        if attr in self.__slots__:
            super(GenericOTRMessage, self).__setattr__(attr, val)
        else:
            self.__getattr__(attr) # existance check
            self.data[attr] = val

    def __repr__(self):
        name = self.__class__.__name__
        data = ''
        for k, _ in self.fields:
            data += '%s=%r,' % (k, self.data[k])
        return '<proto.%s(%s)>' % (name, data)

    @classmethod
    def parsePayload(cls, data):
        data = base64.b64decode(data)
        args = []
        for k, ftype in cls.fields:
            if ftype == 'data':
                value, data = read_data(data)
            elif isinstance(ftype, str):
                size = int(struct.calcsize(ftype))
                value, data = unpack(ftype, data)
            elif isinstance(ftype, int):
                value, data = data[:ftype], data[ftype:]
            args.append(value)
        return cls(*args)

    def getPayload(self, *ffilter):
        payload = ''
        for k, ftype in self.fields:
            if k in ffilter:
                continue

            if ftype == 'data':
                payload += pack_data(self.data[k])
            elif isinstance(ftype, str):
                payload += struct.pack(ftype, self.data[k])
            else:
                payload += self.data[k]
        return payload

class AKEMessage(GenericOTRMessage):
    __slots__ = []
    pass

@registermessage
class DHCommit(AKEMessage):
    __slots__ = []
    msgtype = 0x02
    fields = [('encgx','data'), ('hashgx','data'), ]


@registermessage
class DHKey(AKEMessage):
    __slots__ = []
    msgtype = 0x0a
    fields = [('gy','data'), ]

@registermessage
class RevealSig(AKEMessage):
    __slots__ = []
    msgtype = 0x11
    fields = [('rkey','data'), ('encsig','data'), ('mac',20),]

    def getMacedData(self):
        p = self.encsig
        return struct.pack('!I', len(p)) + p

@registermessage
class Signature(AKEMessage):
    __slots__ = []
    msgtype = 0x12
    fields = [('encsig','data'), ('mac',20)]

    def getMacedData(self):
        p = self.encsig
        return struct.pack('!I', len(p)) + p

@registermessage
class DataMessage(GenericOTRMessage):
    __slots__ = []
    msgtype = 0x03
    fields = [('flags','!B'), ('skeyid','!I'), ('rkeyid','!I'), ('dhy','data'),
            ('ctr',8), ('encmsg','data'), ('mac',20), ('oldmacs','data'), ]

    def getMacedData(self):
        return struct.pack('!HB', self.version, self.msgtype) + \
                self.getPayload('mac', 'oldmacs')

class TLV(object):
    __slots__ = []

    def __repr__(self):
        val = self.getPayload()
        return '<{cls}(typ={t},len={l},val={v!r})>'.format(t=self.typ,
                l=len(val), v=val, cls=self.__class__.__name__)
    def __str__(self):
        val = self.getPayload()
        return struct.pack('!HH', self.typ, len(val)) + val

    @classmethod
    def parse(cls, data):
        if not data:
            return []
        typ, length, data = unpack('!HH', data)
        return [tlvClasses[typ].parsePayload(data[:length])] \
                + cls.parse(data[length:])

@registertlv
class DisconnectTLV(TLV):
    typ = 1
    def __init__(self):
        pass

    def getPayload(self):
        return ''

    @classmethod
    def parsePayload(cls, data):
        if len(data) >  0:
            raise TypeError('DisconnectTLV must not contain data. got {0!r}'
                    .format(data))
        return cls()

class SMPTLV(TLV):
    __slots__ = ['mpis']

    def __init__(self, mpis=[]):
        if len(mpis) != self.dlen:
            raise TypeError('expected {0} mpis, got {1}'
                    .format(self.dlen, count))
        self.mpis = mpis

    def getPayload(self):
        d = struct.pack('!I', len(self.mpis))
        for n in self.mpis:
            d += pack_mpi(n)
        return d

    @classmethod
    def parsePayload(cls, data):
        mpis = []
        if cls.dlen > 0:
            count, data = unpack('!I', data)
            for i in range(count):
                n, data = read_mpi(data)
                mpis.append(n)
        if len(data) > 0:
            raise TypeError('too much data for {0} mpis'.format(cls.dlen))
        return cls(mpis)

@registertlv
class SMP1TLV(SMPTLV):
    typ = 2
    dlen = 6

@registertlv
class SMP1QTLV(SMPTLV):
    typ = 7
    dlen = 6
    __slots__ = ['msg']

    def __init__(self, msg, mpis):
        self.msg = msg
        super(SMP1QTLV, self).__init__(mpis)

    def getPayload(self):
        return self.msg + '\0' + super(SMP1QTLV, self).getPayload()

    @classmethod
    def parsePayload(cls, data):
        msg, data = data.split('\0', 1)
        mpis = SMP1TLV.parsePayload(data).mpis
        return cls(msg, mpis)

@registertlv
class SMP2TLV(SMPTLV):
    typ = 3
    dlen = 11

@registertlv
class SMP3TLV(SMPTLV):
    typ = 4
    dlen = 8

@registertlv
class SMP4TLV(SMPTLV):
    typ = 5
    dlen = 3

@registertlv
class SMPABORTTLV(SMPTLV):
    typ = 6
    dlen = 0

def pack_mpi(n):
    return pack_data(long_to_bytes(n))
def read_mpi(data):
    n, data = read_data(data)
    return bytes_to_long(n), data
def pack_data(data):
    return struct.pack('!I', len(data)) + data
def read_data(data):
    datalen, data= unpack('!I', data)
    return data[:datalen], data[datalen:]
def unpack(fmt, buf):
    s = struct.Struct(fmt)
    return s.unpack(buf[:s.size]) + (buf[s.size:],)

