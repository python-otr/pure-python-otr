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

# some python3 compatibilty
from __future__ import unicode_literals

import logging
import struct
from numbers import Number

from Crypto import Cipher, Random
from Crypto.Hash import SHA256 as _SHA256
from Crypto.Hash import SHA as _SHA1
from Crypto.Hash import HMAC as _HMAC
from Crypto.PublicKey import DSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

from potr import proto


# XXX atfork?
RNG = Random.new()

STATE_NONE = 0
STATE_AWAITING_DHKEY = 1
STATE_AWAITING_REVEALSIG = 2
STATE_AWAITING_SIG = 4
STATE_V1_SETUP = 5


DH1536_MODULUS = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919
DH1536_MODULUS_2 = DH1536_MODULUS-2
DH1536_GENERATOR = 2
SM_ORDER = (DH1536_MODULUS - 1) // 2

def check_group(n):
    return 2 <= n <= DH1536_MODULUS_2
def check_exp(n):
    return 1 <= n < SM_ORDER

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

def human_hash(fp):
    fp = fp.upper()
    fplen = len(fp)
    wordsize = fplen//5
    buf = ''
    for w in range(0, fplen, wordsize):
        buf += '{0} '.format(fp[w:w+wordsize])
    return buf.rstrip()

class Counter(object):
    __slots__ = ['prefix', 'val']
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
        return long_to_bytes(self.prefix).rjust(8, b'\0')

    def __call__(self):
        val = long_to_bytes(self.val)
        prefix = long_to_bytes(self.prefix)
        self.val += 1
        return self.byteprefix() + val.rjust(8, b'\0')

def AESCTR(key, counter=0):
    if isinstance(counter, Number):
        counter = Counter(counter)
    if not isinstance(counter, Counter):
        raise TypeError
    return Cipher.AES.new(key, Cipher.AES.MODE_CTR, counter=counter)

def toMpi(n):
    return toData(long_to_bytes(n))

def toData(s):
    return struct.pack(b'!I', len(s)) + s

def fromMpi(data):
    size, data = proto.unpack(b'!I', data)
    return bytes_to_long(data[:size]), data[size:]

class DH(object):
    __slots__ = ['priv', 'pub']
    @classmethod
    def set_params(cls, prime, gen):
        cls.prime = prime
        cls.gen = gen

    def __init__(self):
        self.priv = bytes_to_long(RNG.read(40))
        self.pub = pow(self.gen, self.priv, self.prime)

DH.set_params(DH1536_MODULUS, DH1536_GENERATOR)

pkTypes = {}
def registerkeytype(cls):
    if not hasattr(cls, 'parsePayload'):
        raise TypeError('registered key types need parsePayload()')
    pkTypes[cls.pubkeyType] = cls
    return cls

class PK(object):
    __slots__ = []
    def sign(self, data):
        raise NotImplementedError
    def verify(self, data):
        raise NotImplementedError
    def fingerprint(self):
        raise NotImplementedError
    def serializePublicKey(self):
        raise NotImplementedError

    def cfingerprint(self):
        return '{0:040x}'.format(bytes_to_long(self.fingerprint()))

    @staticmethod
    def parse(data):
        typeid, data = proto.unpack(b'!H', data)
        cls = pkTypes.get(typeid, None)
        if cls is None:
            raise NotImplementedError('unknown typeid %r' % typeid)
        logging.debug('Got key of type %r' % cls)
        return cls.parsePayload(data)

    def __str__(self):
        return human_hash(self.cfingerprint())
    def __repr__(self):
        return '<{cls}(fpr=\'{fpr}\')>'.format(
                cls=self.__class__.__name__, fpr=str(self))

@registerkeytype
class DSAKey(PK):
    __slots__ = ['priv', 'pub']
    pubkeyType = 0x0000

    def __init__(self, key=None):
        self.priv = self.pub = None
        if isinstance(key, tuple):
            if len(key) == 5:
                self.priv = DSA.construct(key)
                self.pub = self.priv.publickey()
            if len(key) == 4:
                self.pub = DSA.construct(key)
        elif isinstance(key, DSA._DSAobj):
            if key.has_private():
                self.priv = key
                self.pub = self.priv.publickey()
            else:
                self.pub = key

        if self.priv is None and self.pub is None:
            raise TypeError('DSA object or 4/5-tuple required for key')

    def serializePublicKey(self):
        return struct.pack(b'!H', self.pubkeyType) + \
                self.getPayload()

    def getPayload(self):
        return toMpi(self.pub.p) + toMpi(self.pub.q) + \
                toMpi(self.pub.g) + toMpi(self.pub.y)

    def fingerprint(self):
        return SHA1(self.getPayload())

    def sign(self, data):
        # 2 <= K <= q = 160bit = 20 byte
        K = bytes_to_long(RNG.read(19)) + 2
        r, s = self.priv.sign(data, K)
        return long_to_bytes(r) + long_to_bytes(s)

    def verify(self, data, sig):
        r, s = bytes_to_long(sig[:20]), bytes_to_long(sig[20:])
        return self.pub.verify(data, (r,s))

    def __hash__(self):
        return bytes_to_long(self.fingerprint())

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.fingerprint() == other.fingerprint()

    def __ne__(self, other):
        return not (self == other)

    def __getstate__(self):
        if self.priv is not None:
            return (self.priv.y, self.priv.g, self.priv.p, self.priv.q,
                    self.priv.x)
        else:
            return (self.priv.y, self.priv.g, self.priv.p, self.priv.q)

    def __setstate__(self, d):
        self.__init__(d)

    @classmethod
    def generate(cls):
        privkey = DSA.generate(1024)
        return cls((privkey.key.y, privkey.key.g, privkey.key.p, privkey.key.q,
                privkey.key.x))

    @classmethod
    def parsePayload(cls, data):
        p, data = fromMpi(data)
        q, data = fromMpi(data)
        g, data = fromMpi(data)
        y, data = fromMpi(data)
        return cls((y, g, p, q)), data

class DHSession(object):
    __slots__ = ['sendenc', 'sendmac', 'rcvenc', 'rcvmac', 'sendctr', 'rcvctr',
            'sendmacused', 'rcvmacused']
    def __init__(self, sendenc, sendmac, rcvenc, rcvmac):
        self.sendenc = sendenc
        self.sendmac = sendmac
        self.rcvenc = rcvenc
        self.rcvmac = rcvmac
        self.sendctr = Counter(0)
        self.rcvctr = Counter(0)
        self.sendmacused = False
        self.rcvmacused = False

    def __repr__(self):
        return '<{cls}(send={s!r},rcv={r!r})>' \
                .format(cls=self.__class__.__name__,
                        s=self.sendmac, r=self.rcvmac)

    @classmethod
    def create(cls, dh, y):
        s = pow(y, dh.priv, DH1536_MODULUS)
        sb = toMpi(s)

        if dh.pub > y:
            sendbyte = b'\1'
            rcvbyte = b'\2'
        else:
            sendbyte = b'\2'
            rcvbyte = b'\1'

        sendenc = SHA1(sendbyte + sb)[:16]
        sendmac = SHA1(sendenc)
        rcvenc = SHA1(rcvbyte + sb)[:16]
        rcvmac = SHA1(rcvenc)
        return cls(sendenc, sendmac, rcvenc, rcvmac)

class CryptEngine(object):
    __slots__ = ['ctx', 'ake', 'sessionId', 'sessionIdHalf', 'theirKeyid',
            'theirY', 'theirOldY', 'ourOldDHKey', 'ourDHKey', 'ourKeyid',
            'sessionkeys', 'theirPubkey', 'savedMacKeys', 'smp']
    def __init__(self, ctx):
        self.ctx = ctx
        self.ake = None

        self.sessionId = None
        self.sessionIdHalf = False
        self.theirKeyid = 0
        self.theirY = None
        self.theirOldY = None

        self.ourOldDHKey = None
        self.ourDHKey = None
        self.ourKeyid = 0

        self.sessionkeys = {0:{0:None, 1:None}, 1:{0:None, 1:None}}
        self.theirPubkey = None
        self.savedMacKeys = []

        self.smp = None

    def revealMacs(self, ours=True):
        if ours:
            dhs = self.sessionkeys[1].values()
        else:
            dhs = ( v[1] for v in self.sessionkeys.values() )
        for v in dhs:
            if v is not None:
                if v.rcvmacused:
                    self.savedMacKeys.append(v.rcvmac)
                if v.sendmacused:
                    self.savedMacKeys.append(v.sendmac)

    def rotateDHKeys(self):
        self.revealMacs(ours=True)
        self.ourOldDHKey = self.ourDHKey
        self.sessionkeys[1] = self.sessionkeys[0].copy()
        self.ourDHKey = DH()
        self.ourKeyid += 1

        self.sessionkeys[0][0] = None if self.theirY is None else \
                DHSession.create(self.ourDHKey, self.theirY)
        self.sessionkeys[0][1] = None if self.theirOldY is None else \
                DHSession.create(self.ourDHKey, self.theirOldY)

        logging.debug('{0}: Refreshing ourkey to {1} {2}'.format(
                self.ctx.user.name, self.ourKeyid, self.sessionkeys))

    def rotateYKeys(self, new_y):
        self.theirOldY = self.theirY
        self.revealMacs(ours=False)
        self.sessionkeys[0][1] = self.sessionkeys[0][0]
        self.sessionkeys[1][1] = self.sessionkeys[1][0]
        self.theirY = new_y
        self.theirKeyid += 1

        self.sessionkeys[0][0] = DHSession.create(self.ourDHKey, self.theirY)
        self.sessionkeys[1][0] = DHSession.create(self.ourOldDHKey, self.theirY)

        logging.debug('{0}: Refreshing theirkey to {1} {2}'.format(
                self.ctx.user.name, self.theirKeyid, self.sessionkeys))

    def handleDataMessage(self, msg):
        if self.saneKeyIds(msg) is False:
            raise InvalidParameterError

        sesskey = self.sessionkeys[self.ourKeyid - msg.rkeyid] \
                [self.theirKeyid - msg.skeyid]

        logging.debug('sesskeys: {0!r}, our={1}, r={2}, their={3}, s={4}' \
                .format(self.sessionkeys, self.ourKeyid, msg.rkeyid,
                        self.theirKeyid, msg.skeyid))

        if msg.mac != SHA1HMAC(sesskey.rcvmac, msg.getMacedData()):
            logging.error('HMACs don\'t match')
            raise InvalidParameterError
        sesskey.rcvmacused = 1

        newCtrPrefix = bytes_to_long(msg.ctr)
        if newCtrPrefix <= sesskey.rcvctr.prefix:
            logging.error('CTR must increase (old %r, new %r)',
                    sesskey.rcvctr.prefix, newCtrPrefix)
            raise InvalidParameterError

        sesskey.rcvctr.prefix = newCtrPrefix

        logging.debug('handle: enc={0!r} mac={1!r} ctr={2!r}' \
                .format(sesskey.rcvenc, sesskey.rcvmac, sesskey.rcvctr))

        plaintextData = AESCTR(sesskey.rcvenc, sesskey.rcvctr) \
                .decrypt(msg.encmsg)

        if b'\0' in plaintextData:
            plaintext, tlvData = plaintextData.split(b'\0', 1)
            tlvs = proto.TLV.parse(tlvData)
        else:
            plaintext = plaintextData
            tlvs = []

        if msg.rkeyid == self.ourKeyid:
            self.rotateDHKeys()
        if msg.skeyid == self.theirKeyid:
            self.rotateYKeys(bytes_to_long(msg.dhy))

        return plaintext, tlvs

    def smpSecret(self, secret, question=None, appdata=None):
        if self.smp is None:
            logging.debug('Creating SMPHandler')
            self.smp = SMPHandler(self)

        self.smp.gotSecret(secret, question=question, appdata=appdata)

    def smpHandle(self, tlv, appdata=None):
        if self.smp is None:
            logging.debug('Creating SMPHandler')
            self.smp = SMPHandler(self)
        self.smp.handle(tlv, appdata=appdata)

    def smpAbort(self, appdata=None):
        if self.smp is None:
            logging.debug('Creating SMPHandler')
            self.smp = SMPHandler(self)
        self.smp.abort(appdata=appdata)

    def createDataMessage(self, message, flags=0, tlvs=[]):
        # check MSGSTATE
        if self.theirKeyid == 0:
            raise InvalidParameterError

        sess = self.sessionkeys[1][0]
        sess.sendctr.inc()

        logging.debug('create: enc={0!r} mac={1!r} ctr={2!r}' \
                .format(sess.sendenc, sess.sendmac, sess.sendctr))

        # plaintext + TLVS
        plainBuf = message + b'\0' + b''.join([ bytes(t) for t in tlvs])
        encmsg = AESCTR(sess.sendenc, sess.sendctr).encrypt(plainBuf)

        msg = proto.DataMessage(flags, self.ourKeyid-1, self.theirKeyid,
                long_to_bytes(self.ourDHKey.pub), sess.sendctr.byteprefix(),
                encmsg, b'', b''.join(self.savedMacKeys))
        msg.mac = SHA1HMAC(sess.sendmac, msg.getMacedData())
        return msg

    def saneKeyIds(self, msg):
        anyzero = self.theirKeyid == 0 or msg.skeyid == 0 or msg.rkeyid == 0
        if anyzero or (msg.skeyid != self.theirKeyid and \
                msg.skeyid != self.theirKeyid - 1) or \
                (msg.rkeyid != self.ourKeyid and msg.rkeyid != self.ourKeyid - 1):
            return False
        if self.theirOldY is None and msg.skeyid == self.theirKeyid - 1:
            return False
        return True

    def startAKE(self, appdata=None):
        self.ake = AuthKeyExchange(self.ctx.user.getPrivkey(), self.goEncrypted)
        outMsg = self.ake.startAKE()
        self.ctx.inject(outMsg, appdata=appdata)

    def handleAKE(self, inMsg, appdata=None):
        outMsg = None

        if not self.ctx.getPolicy('ALLOW_V2'):
            return

        if isinstance(inMsg, proto.DHCommit):
            if self.ake is None or self.ake.state != STATE_AWAITING_REVEALSIG:
                self.ake = AuthKeyExchange(self.ctx.user.getPrivkey(),
                        self.goEncrypted)
            outMsg = self.ake.handleDHCommit(inMsg)

        elif isinstance(inMsg, proto.DHKey):
            if self.ake is None:
                return # ignore
            outMsg = self.ake.handleDHKey(inMsg)

        elif isinstance(inMsg, proto.RevealSig):
            if self.ake is None:
                return # ignore
            outMsg = self.ake.handleRevealSig(inMsg)

        elif isinstance(inMsg, proto.Signature):
            if self.ake is None:
                return # ignore
            self.ake.handleSignature(inMsg)

        if outMsg is not None:
            self.ctx.inject(outMsg, appdata=appdata)

    def goEncrypted(self, ake):
        if ake.dh.pub == ake.gy:
            logging.warning('We are receiving our own messages')
            raise InvalidParameterError

        # TODO handle new fingerprint
        self.theirPubkey = ake.theirPubkey

        self.sessionId = ake.sessionId
        self.sessionIdHalf = ake.sessionIdHalf
        self.theirKeyid = ake.theirKeyid
        self.ourKeyid = ake.ourKeyid
        self.theirY = ake.gy
        self.theirOldY = None

        if self.ourKeyid != ake.ourKeyid + 1 or self.ourOldDHKey != ake.dh.pub:
            # XXX is this really ok?
            self.ourDHKey = ake.dh
            self.sessionkeys[0][0] = DHSession.create(self.ourDHKey, self.theirY)
            self.rotateDHKeys()

        self.ctx._wentEncrypted()
        logging.info('went encrypted with {0}'.format(self.theirPubkey))

    def finished(self):
        self.smp = None

class AuthKeyExchange(object):
    __slots__ = ['privkey', 'state', 'r', 'encgx', 'hashgx', 'ourKeyid',
            'theirPubkey', 'theirKeyid', 'enc_c', 'enc_cp', 'mac_m1',
            'mac_m1p', 'mac_m2', 'mac_m2p', 'sessionId', 'dh', 'onSuccess',
            'gy', 'lastmsg', 'sessionIdHalf']
    def __init__(self, privkey, onSuccess):
        self.privkey = privkey
        self.state = STATE_NONE
        self.r = None
        self.encgx = None
        self.hashgx = None
        self.ourKeyid = 1
        self.theirPubkey = None
        self.theirKeyid = 1
        self.enc_c = None
        self.enc_cp = None
        self.mac_m1 = None
        self.mac_m1p = None
        self.mac_m2 = None
        self.mac_m2p = None
        self.sessionId = None
        self.sessionIdHalf = False
        self.dh = DH()
        self.onSuccess = onSuccess
        self.gy = None

    def startAKE(self):
        self.r = RNG.read(16)

        gxmpi = toMpi(self.dh.pub)

        self.hashgx = SHA256(gxmpi)
        self.encgx = AESCTR(self.r).encrypt(gxmpi)

        self.state = STATE_AWAITING_DHKEY

        return proto.DHCommit(self.encgx, self.hashgx)

    def handleDHCommit(self, msg):
        self.encgx = msg.encgx
        self.hashgx = msg.hashgx

        self.state = STATE_AWAITING_REVEALSIG
        return proto.DHKey(long_to_bytes(self.dh.pub))

    def handleDHKey(self, msg):
        if self.state == STATE_AWAITING_DHKEY:
            self.gy = bytes_to_long(msg.gy)

            # check 2 <= g**y <= p-2
            if not check_group(self.gy):
                logging.error('Invalid g**y received: %r', self.gy)
                return

            self.createAuthKeys()

            aesxb = self.calculatePubkeyAuth(self.enc_c, self.mac_m1)

            self.state = STATE_AWAITING_SIG

            self.lastmsg = proto.RevealSig(self.r, aesxb, b'')
            self.lastmsg.mac = SHA256HMAC160(self.mac_m2,
                    self.lastmsg.getMacedData())
            return self.lastmsg

        elif self.state == STATE_AWAITING_SIG:
            logging.info('received DHKey while not awaiting DHKEY')
            if msg.gy == self.gy:
                logging.info('resending revealsig')
                return self.lastmsg
        else:
            logging.info('bad state for DHKey')

    def handleRevealSig(self, msg):
        if self.state != STATE_AWAITING_REVEALSIG:
            logging.error('bad state for RevealSig')
            raise InvalidParameterError

        self.r = msg.rkey
        gxmpi = AESCTR(self.r).decrypt(self.encgx)
        if SHA256(gxmpi) != self.hashgx:
            logging.error('Hashes don\'t match')
            logging.info('r=%r, hashgx=%r, computed hash=%r, gxmpi=%r',
                    self.r, self.hashgx, SHA256(gxmpi), gxmpi)
            raise InvalidParameterError

        self.gy = fromMpi(gxmpi)[0]
        self.createAuthKeys()

        if msg.mac != SHA256HMAC160(self.mac_m2, msg.getMacedData()):
            logging.error('HMACs don\'t match')
            logging.info('mac=%r, mac_m2=%r, data=%r', msg.mac, self.mac_m2,
                    msg.getMacedData())
            raise InvalidParameterError

        self.checkPubkeyAuth(self.enc_c, self.mac_m1, msg.encsig)

        aesxb = self.calculatePubkeyAuth(self.enc_cp, self.mac_m1p)
        self.sessionIdHalf = True

        self.onSuccess(self)

        self.ourKeyid = 0
        self.state = STATE_NONE

        cmpmac = struct.pack(b'!I', len(aesxb)) + aesxb

        return proto.Signature(aesxb, SHA256HMAC160(self.mac_m2p, cmpmac))

    def handleSignature(self, msg):
        if self.state != STATE_AWAITING_SIG:
            logging.error('bad state (%d) for Signature', self.state)
            raise InvalidParameterError

        if msg.mac != SHA256HMAC160(self.mac_m2p, msg.getMacedData()):
            logging.error('HMACs don\'t match')
            raise InvalidParameterError

        self.checkPubkeyAuth(self.enc_cp, self.mac_m1p, msg.encsig)

        self.sessionIdHalf = False

        self.onSuccess(self)

        self.ourKeyid = 0
        self.state = STATE_NONE

    def createAuthKeys(self):
        s = pow(self.gy, self.dh.priv, DH1536_MODULUS)
        sbyte = toMpi(s)
        self.sessionId = SHA256(b'\0' + sbyte)[:8]
        enc = SHA256(b'\1' + sbyte)
        self.enc_c, self.enc_cp = enc[:16], enc[16:]
        self.mac_m1 = SHA256(b'\2' + sbyte)
        self.mac_m2 = SHA256(b'\3' + sbyte)
        self.mac_m1p = SHA256(b'\4' + sbyte)
        self.mac_m2p = SHA256(b'\5' + sbyte)

    def calculatePubkeyAuth(self, key, mackey):
        pubkey = self.privkey.serializePublicKey()
        buf = toMpi(self.dh.pub)
        buf += toMpi(self.gy)
        buf += pubkey
        buf += struct.pack(b'!I', self.ourKeyid)
        MB = self.privkey.sign(SHA256HMAC(mackey, buf))

        buf = pubkey
        buf += struct.pack(b'!I', self.ourKeyid)
        buf += MB
        return AESCTR(key).encrypt(buf)

    def checkPubkeyAuth(self, key, mackey, encsig):
        auth = AESCTR(key).decrypt(encsig)
        self.theirPubkey, auth = PK.parse(auth)

        receivedKeyid, auth = proto.unpack(b'!I', auth)
        if receivedKeyid == 0:
            raise InvalidParameterError

        authbuf = toMpi(self.gy)
        authbuf += toMpi(self.dh.pub)
        authbuf += self.theirPubkey.serializePublicKey()
        authbuf += struct.pack(b'!I', receivedKeyid)

        if self.theirPubkey.verify(SHA256HMAC(mackey, authbuf), auth) is False:
            raise InvalidParameterError
        self.theirKeyid = receivedKeyid

SMPPROG_OK = 0
SMPPROG_CHEATED = -2
SMPPROG_FAILED = -1
SMPPROG_SUCCEEDED = 1

class SMPHandler:
    __slots__ = ['crypto', 'question', 'prog', 'state', 'g1', 'g3o', 'x2',
            'x3', 'g2', 'g3', 'pab', 'qab', 'secret', 'p', 'q']

    def __init__(self, crypto):
        self.crypto = crypto
        self.state = 1
        self.g1 = DH1536_GENERATOR
        self.g3o = None
        self.prog = SMPPROG_OK
        self.pab = None
        self.qab = None
        self.question = False
        self.secret = None
        self.p = None
        self.q = None

    def abort(self, appdata=None):
        self.state = 1
        self.sendTLV(proto.SMPABORTTLV(), appdata=appdata)

    def sendTLV(self, tlv, appdata=None):
        self.crypto.ctx.inject(self.crypto.createDataMessage(b'',
                flags=proto.MSGFLAGS_IGNORE_UNREADABLE, tlvs=[tlv]),
                appdata=appdata)

    def handle(self, tlv, appdata=None):
        logging.debug('handling TLV {0.__class__.__name__}'.format(tlv))
        self.prog = SMPPROG_CHEATED
        if isinstance(tlv, proto.SMPABORTTLV):
            self.state = 1
            return
        if isinstance(tlv, (proto.SMP1TLV, proto.SMP1QTLV)):
            if self.state != 1:
                self.abort(appdata=appdata)
                return

            msg = tlv.mpis

            if not check_group(msg[0]) or not check_group(msg[3]) \
                    or not check_exp(msg[2]) or not check_exp(msg[5]) \
                    or not check_known_log(msg[1], msg[2], self.g1, msg[0], 1) \
                    or not check_known_log(msg[4], msg[5], self.g1, msg[3], 2):
                logging.error('invalid SMP1TLV received')
                self.abort(appdata=appdata)
                return

            self.g3o = msg[3]

            self.x2 = bytes_to_long(RNG.read(192))
            self.x3 = bytes_to_long(RNG.read(192))

            self.g2 = pow(msg[0], self.x2, DH1536_MODULUS)
            self.g3 = pow(msg[3], self.x3, DH1536_MODULUS)

            self.prog = SMPPROG_OK
            self.state = 0
            return
        if isinstance(tlv, proto.SMP2TLV):
            if self.state != 2:
                self.abort(appdata=appdata)
                return

            msg = tlv.mpis
            mp = msg[6]
            mq = msg[7]

            if not check_group(msg[0]) or not check_group(msg[3]) \
                    or not check_group(msg[6]) or not check_group(msg[7]) \
                    or not check_exp(msg[2]) or not check_exp(msg[5]) \
                    or not check_exp(msg[9]) or not check_exp(msg[10]) \
                    or not check_known_log(msg[1], msg[2], self.g1, msg[0], 3) \
                    or not check_known_log(msg[4], msg[5], self.g1, msg[3], 4):
                logging.error('invalid SMP2TLV received')
                self.abort(appdata=appdata)
                return

            self.g3o = msg[3]
            self.g2 = pow(msg[0], self.x2, DH1536_MODULUS)
            self.g3 = pow(msg[3], self.x3, DH1536_MODULUS)

            if not self.check_equal_coords(msg[6:11], 5):
                logging.error('invalid SMP2TLV received')
                self.abort(appdata=appdata)
                return

            r = bytes_to_long(RNG.read(192))
            self.p = pow(self.g3, r, DH1536_MODULUS)
            msg = [self.p]
            qa1 = pow(self.g1, r, DH1536_MODULUS)
            qa2 = pow(self.g2, self.secret, DH1536_MODULUS)
            self.q = qa1*qa2 % DH1536_MODULUS
            msg.append(self.q)
            msg += self.proof_equal_coords(r, 6)

            inv = invMod(mp)
            self.pab = self.p * inv % DH1536_MODULUS
            inv = invMod(mq)
            self.qab = self.q * inv % DH1536_MODULUS

            msg.append(pow(self.qab, self.x3, DH1536_MODULUS))
            msg += self.proof_equal_logs(7)

            self.state = 4
            self.prog = SMPPROG_OK
            self.sendTLV(proto.SMP3TLV(msg), appdata=appdata)
            return
        if isinstance(tlv, proto.SMP3TLV):
            if self.state != 3:
                self.abort(appdata=appdata)
                return

            msg = tlv.mpis

            if not check_group(msg[0]) or not check_group(msg[1]) \
                    or not check_group(msg[5]) or not check_exp(msg[3]) \
                    or not check_exp(msg[4]) or not check_exp(msg[7]) \
                    or not self.check_equal_coords(msg[:5], 6):
                logging.error('invalid SMP3TLV received')
                self.abort(appdata=appdata)
                return

            inv = invMod(self.p)
            self.pab = msg[0] * inv % DH1536_MODULUS
            inv = invMod(self.q)
            self.qab = msg[1] * inv % DH1536_MODULUS

            if not self.check_equal_logs(msg[5:8], 7):
                logging.error('invalid SMP3TLV received')
                self.abort(appdata=appdata)
                return

            md = msg[5]
            msg = [pow(self.qab, self.x3, DH1536_MODULUS)]
            msg += self.proof_equal_logs(8)

            rab = pow(md, self.x3, DH1536_MODULUS)
            self.prog = SMPPROG_SUCCEEDED if self.pab == rab else SMPPROG_FAILED

            if self.prog != SMPPROG_SUCCEEDED:
                logging.error('secrets don\'t match')
                self.abort(appdata=appdata)
                self.crypto.ctx.setCurrentTrust('')
                return

            logging.info('secrets matched')
            self.crypto.ctx.setCurrentTrust('smp')
            self.state = 1
            self.sendTLV(proto.SMP4TLV(msg), appdata=appdata)
            return
        if isinstance(tlv, proto.SMP4TLV):
            if self.state != 4:
                self.abort(appdata=appdata)
                return

            msg = tlv.mpis

            if not check_group(msg[0]) or not check_exp(msg[2]) \
                    or not self.check_equal_logs(msg[:3], 8):
                logging.error('invalid SMP4TLV received')
                self.abort(appdata=appdata)
                return

            rab = pow(msg[0], self.x3, DH1536_MODULUS)

            self.prog = SMPPROG_SUCCEEDED if self.pab == rab else SMPPROG_FAILED

            if self.prog != SMPPROG_SUCCEEDED:
                logging.error('secrets don\'t match')
                self.abort(appdata=appdata)
                self.crypto.ctx.setCurrentTrust('')
                return

            logging.info('secrets matched')
            self.crypto.ctx.setCurrentTrust('smp')
            self.state = 1
            return

    def gotSecret(self, secret, question=None, appdata=None):
        ourFP = self.crypto.ctx.user.getPrivkey().fingerprint()
        if self.state == 1:
            # first secret -> SMP1TLV
            combSecret = SHA256(b'\1' + ourFP +
                    self.crypto.theirPubkey.fingerprint() +
                    self.crypto.sessionId + secret)

            self.secret = bytes_to_long(combSecret)

            self.x2 = bytes_to_long(RNG.read(192))
            self.x3 = bytes_to_long(RNG.read(192))

            msg = [pow(self.g1, self.x2, DH1536_MODULUS)]
            msg += proof_known_log(self.g1, self.x2, 1)
            msg.append(pow(self.g1, self.x3, DH1536_MODULUS))
            msg += proof_known_log(self.g1, self.x3, 2)

            self.prog = SMPPROG_OK
            self.state = 2
            if question is None:
                self.sendTLV(proto.SMP1TLV(msg), appdata=appdata)
            else:
                self.sendTLV(proto.SMP1QTLV(question, msg), appdata=appdata)
        if self.state == 0:
            # response secret -> SMP2TLV
            combSecret = SHA256(b'\1' + self.crypto.theirPubkey.fingerprint() +
                    ourFP + self.crypto.sessionId + secret)

            self.secret = bytes_to_long(combSecret)

            msg = [pow(self.g1, self.x2, DH1536_MODULUS)]
            msg += proof_known_log(self.g1, self.x2, 3)
            msg.append(pow(self.g1, self.x3, DH1536_MODULUS))
            msg += proof_known_log(self.g1, self.x3, 4)

            r = bytes_to_long(RNG.read(192))

            self.p = pow(self.g3, r, DH1536_MODULUS)
            msg.append(self.p)

            qb1 = pow(self.g1, r, DH1536_MODULUS)
            qb2 = pow(self.g2, self.secret, DH1536_MODULUS)
            self.q = qb1 * qb2 % DH1536_MODULUS
            msg.append(self.q)

            msg += self.proof_equal_coords(r, 5)

            self.state = 3
            self.sendTLV(proto.SMP2TLV(msg), appdata=appdata)

    def proof_equal_coords(self, r, v):
        r1 = bytes_to_long(RNG.read(192))
        r2 = bytes_to_long(RNG.read(192))
        temp2 = pow(self.g1, r1, DH1536_MODULUS) \
                * pow(self.g2, r2, DH1536_MODULUS) % DH1536_MODULUS
        temp1 = pow(self.g3, r1, DH1536_MODULUS)

        cb = SHA256(chr(v) + toMpi(temp1) + toMpi(temp2))
        c = bytes_to_long(cb)

        temp1 = r * c % SM_ORDER
        d1 = (r1-temp1) % SM_ORDER

        temp1 = self.secret * c % SM_ORDER
        d2 = (r2 - temp1) % SM_ORDER
        return c, d1, d2

    def check_equal_coords(self, coords, v):
        (p, q, c, d1, d2) = coords
        temp1 = pow(self.g3, d1, DH1536_MODULUS) * pow(p, c, DH1536_MODULUS) \
                % DH1536_MODULUS

        temp2 = pow(self.g1, d1, DH1536_MODULUS) \
                * pow(self.g2, d2, DH1536_MODULUS) \
                * pow(q, c, DH1536_MODULUS) % DH1536_MODULUS

        cprime = SHA256(chr(v) + toMpi(temp1) + toMpi(temp2))

        return long_to_bytes(c) == cprime

    def proof_equal_logs(self, v):
        r = bytes_to_long(RNG.read(192))
        temp1 = pow(self.g1, r, DH1536_MODULUS)
        temp2 = pow(self.qab, r, DH1536_MODULUS)

        cb = SHA256(chr(v) + toMpi(temp1) + toMpi(temp2))
        c = bytes_to_long(cb)
        temp1 = self.x3 * c % SM_ORDER
        d = (r - temp1) % SM_ORDER
        return c, d

    def check_equal_logs(self, logs, v):
        (r, c, d) = logs
        temp1 = pow(self.g1, d, DH1536_MODULUS) \
                * pow(self.g3o, c, DH1536_MODULUS) % DH1536_MODULUS

        temp2 = pow(self.qab, d, DH1536_MODULUS) \
                * pow(r, c, DH1536_MODULUS) % DH1536_MODULUS

        cprime = SHA256(chr(v) + toMpi(temp1) + toMpi(temp2))
        return long_to_bytes(c) == cprime

def proof_known_log(g, x, v):
    r = bytes_to_long(RNG.read(192))
    c = bytes_to_long(SHA256(chr(v) + toMpi(pow(g, r, DH1536_MODULUS))))
    temp = x * c % SM_ORDER
    return c, (r-temp) % SM_ORDER

def check_known_log(c, d, g, x, v):
    gd = pow(g, d, DH1536_MODULUS)
    xc = pow(x, c, DH1536_MODULUS)
    gdxc = gd * xc % DH1536_MODULUS
    return SHA256(chr(v) + toMpi(gdxc)) == long_to_bytes(c)

def invMod(n):
    return pow(n, DH1536_MODULUS_2, DH1536_MODULUS)

class InvalidParameterError(RuntimeError):
    pass
