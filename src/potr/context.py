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
from __future__ import print_function
from __future__ import unicode_literals

try:
    basestring = basestring
except NameError:
    # all strings are unicode in python3k
    basestring = str
    unicode = str

# callable is not available in python 3.0 and 3.1
try:
    callable = callable
except NameError:
    from collections import Callable
    def callable(x):
        return isinstance(x, Callable)


import base64
import logging
import struct

from potr import crypt
from potr import proto

from time import time

EXC_UNREADABLE_MESSAGE = 1
EXC_FINISHED = 2

HEARTBEAT_INTERVAL = 60
STATE_PLAINTEXT = 0
STATE_ENCRYPTED = 1
STATE_FINISHED = 2
FRAGMENT_SEND_ALL = 0
FRAGMENT_SEND_ALL_BUT_FIRST = 1
FRAGMENT_SEND_ALL_BUT_LAST = 2

OFFER_NOTSENT = 0
OFFER_SENT = 1
OFFER_REJECTED = 2
OFFER_ACCEPTED = 3

class Context(object):
    __slots__ = ['user', 'policy', 'crypto', 'tagOffer', 'lastSend',
            'lastMessage', 'mayRetransmit', 'fragment', 'fragmentInfo', 'state',
            'inject', 'trust', 'peer']

    def __init__(self, account, peername):
        self.user = account
        self.peer = peername
        self.policy = {}
        self.trust = {}
        self.crypto = crypt.CryptEngine(self)
        self.discardFragment()
        self.tagOffer = OFFER_NOTSENT
        self.mayRetransmit = 0
        self.lastSend = 0
        self.lastMessage = None
        self.state = STATE_PLAINTEXT

    def getPolicy(self, key):
        raise NotImplementedError

    def inject(self, msg, appdata=None):
        raise NotImplementedError

    def policyOtrEnabled(self):
        return self.getPolicy('ALLOW_V2') or self.getPolicy('ALLOW_V1')

    def discardFragment(self):
        self.fragmentInfo = (0, 0)
        self.fragment = []

    def fragmentAccumulate(self, message):
        '''Accumulate a fragmented message. Returns None if the fragment is
        to be ignored, returns a string if the message is ready for further
        processing'''

        params = message.split(b',')
        if len(params) < 5 or not params[1].isdigit() or not params[2].isdigit():
            logging.warning('invalid formed fragmented message: %r', params)
            return None


        K, N = self.fragmentInfo

        k = int(params[1])
        n = int(params[2])
        fragData = params[3]

        logging.debug(params)

        if n >= k == 1:
            # first fragment
            self.discardFragment()
            self.fragmentInfo = (k,n)
            self.fragment.append(fragData)
        elif N == n >= k > 1 and k == K+1:
            # accumulate
            self.fragmentInfo = (k,n)
            self.fragment.append(fragData)
        else:
            # bad, discard
            self.discardFragment()
            logging.warning('invalid fragmented message: %r', params)
            return None

        if n == k > 0:
            assembled = b''.join(self.fragment)
            self.discardFragment()
            return assembled

        return None

    def removeFingerprint(self, fingerprint):
        if fingerprint in self.trust:
            del self.trust[fingerprint]

    def setTrust(self, fingerprint, trustLevel):
        ''' sets the trust level for the given fingerprint.
        trust is usually:
            - the empty string for known but untrusted keys
            - 'verified' for manually verified keys
            - 'smp' for smp-style verified keys '''
        self.trust[fingerprint] = trustLevel

    def getTrust(self, fingerprint):
        return self.trust.get(fingerprint, None)

    def setCurrentTrust(self, trustLevel):
        self.setTrust(self.crypto.theirPubkey.cfingerprint(), trustLevel)
        self.user.saveTrusts()

    def getCurrentKey(self):
        return self.crypto.theirPubkey

    def getCurrentTrust(self):
        ''' returns a 2-tuple: first element is the current fingerprint,
            second is:
            - None if the key is unknown yet
            - a non-empty string if the key is trusted
            - an empty string if the key is untrusted '''
        if self.crypto.theirPubkey is None:
            return None
        return self.trust.get(self.crypto.theirPubkey.cfingerprint(), None)

    def receiveMessage(self, messageData, appdata=None):
        IGN = None, []

        if not self.policyOtrEnabled():
            return (messageData, [])

        message = self.parse(messageData)

        if message is None:
            # nothing to see. move along.
            return IGN

        logging.debug(repr(message))

        if self.getPolicy('SEND_TAG'):
            if isinstance(message, basestring):
                self.tagOffer = OFFER_REJECTED
            else:
                self.tagOffer = OFFER_ACCEPTED

        if isinstance(message, proto.Query):
            self.handleQuery(message, appdata=appdata)

            if isinstance(message, proto.TaggedPlaintext):
                # it's actually a plaintext message
                if self.state != STATE_PLAINTEXT or \
                        self.getPolicy('REQUIRE_ENCRYPTION'):
                    # but we don't want plaintexts
                    raise UnencryptedMessage(message.msg)

                return (message.msg, [])

            return IGN

        if isinstance(message, proto.AKEMessage):
            self.crypto.handleAKE(message, appdata=appdata)
            return IGN

        if isinstance(message, proto.DataMessage):
            ignore = message.flags & proto.MSGFLAGS_IGNORE_UNREADABLE

            if self.state != STATE_ENCRYPTED:
                self.sendInternal(proto.Error(
                        'You sent encrypted to {user}, who wasn\'t expecting it.'
                            .format(user=self.user.name)), appdata=appdata)
                if ignore:
                    return IGN
                raise NotEncryptedError(EXC_UNREADABLE_MESSAGE)

            try:
                plaintext, tlvs = self.crypto.handleDataMessage(message)
                self.processTLVs(tlvs, appdata=appdata)
                if plaintext and self.lastSend < time() - HEARTBEAT_INTERVAL:
                    self.sendInternal(b'', appdata=appdata)
                return plaintext or None, tlvs
            except crypt.InvalidParameterError:
                if ignore:
                    return IGN
                logging.exception('decryption failed')
                raise
        if isinstance(message, basestring):
            if self.state != STATE_PLAINTEXT or \
                    self.getPolicy('REQUIRE_ENCRYPTION'):
                raise UnencryptedMessage(message)

        if isinstance(message, proto.Error):
            raise ErrorReceived(message)

        return message, []

    def sendInternal(self, msg, tlvs=[], appdata=None):
        if isinstance(msg, basestring):
            self.sendMessage(FRAGMENT_SEND_ALL, msg,
                    flags=proto.MSGFLAGS_IGNORE_UNREADABLE, tlvs=tlvs,
                    appdata=appdata)
        else:
            self.sendFragmented(FRAGMENT_SEND_ALL, bytes(msg), appdata=appdata)

    def sendMessage(self, sendPolicy, msg, flags=0, tlvs=[], appdata=None):
        if self.policyOtrEnabled():
            self.lastSend = time()
            msg = bytes(self.processOutgoingMessage(msg, flags, tlvs))
        return self.sendFragmented(sendPolicy, msg, appdata=appdata)

    def processOutgoingMessage(self, msg, flags, tlvs=[]):
        if isinstance(self.parse(msg), proto.Query):
            msg = self.user.getDefaultQueryMessage(self.getPolicy)

        if self.state == STATE_PLAINTEXT:
            if self.getPolicy('REQUIRE_ENCRYPTION'):
                if not isinstance(self.parse(msg), proto.Query):
                    self.lastMessage = msg
                    self.lastSend = time()
                    self.mayRetransmit = 2
                    # TODO notify
                    msg = self.user.getDefaultQueryMessage(self.getPolicy)
                return msg
            if self.getPolicy('SEND_TAG') and self.tagOffer != OFFER_REJECTED:
                self.tagOffer = OFFER_SENT
                return proto.TaggedPlaintext(msg, self.getPolicy('ALLOW_V1'),
                        self.getPolicy('ALLOW_V2'))
            return msg
        if self.state == STATE_ENCRYPTED:
            msg = self.crypto.createDataMessage(msg, flags, tlvs)
            self.lastSend = time()
            return msg
        if self.state == STATE_FINISHED:
            raise NotEncryptedError(EXC_FINISHED)

    def disconnect(self, appdata=None):
        if self.state != STATE_FINISHED:
            self.sendInternal(b'', tlvs=[proto.DisconnectTLV()], appdata=appdata)
            self.setState(STATE_PLAINTEXT)
            self.crypto.finished()
        else:
            self.setState(STATE_PLAINTEXT)

    def setState(self, newstate):
        self.state = newstate

    def _wentEncrypted(self):
        self.setState(STATE_ENCRYPTED)

    def sendFragmented(self, sendPolicy, msg, appdata=None):
        mms = self.user.maxMessageSize
        msgLen = len(msg)
        if mms != 0 and len(msg) > mms and self.policyOtrEnabled() \
                and self.state == STATE_ENCRYPTED:
            fms = mms - 19
            fragments = [ msg[i:i+fms] for i in range(0, len(msg), fms) ]

            fc = len(fragments)

            if fc > 65535:
                raise OverflowError('too many fragments')

            for fi in range(len(fragments)):
                ctr = unicode(fi+1) + ',' + unicode(fc) + ','
                fragments[fi] = b'?OTR,' + ctr.encode('ascii') \
                        + fragments[fi] + b','

            if sendPolicy == FRAGMENT_SEND_ALL:
                for f in fragments:
                    self.inject(f, appdata=appdata)
                return None
            elif sendPolicy == FRAGMENT_SEND_ALL_BUT_FIRST:
                for f in fragments[1:]:
                    self.inject(f, appdata=appdata)
                return fragments[0]
            elif sendPolicy == FRAGMENT_SEND_ALL_BUT_LAST:
                for f in fragments[:-1]:
                    self.inject(f, appdata=appdata)
                return fragments[-1]

        else:
            if sendPolicy == FRAGMENT_SEND_ALL:
                self.inject(msg, appdata=appdata)
                return None
            else:
                return msg

    def processTLVs(self, tlvs, appdata=None):
        for tlv in tlvs:
            if isinstance(tlv, proto.DisconnectTLV):
                logging.info('got disconnect tlv, forcing finished state')
                self.setState(STATE_FINISHED)
                self.crypto.finished()
                # TODO cleanup
                continue
            if isinstance(tlv, proto.SMPTLV):
                self.crypto.smpHandle(tlv, appdata=appdata)
                continue
            logging.info('got unhandled tlv: {0!r}'.format(tlv))

    def smpAbort(self, appdata=None):
        if self.state != STATE_ENCRYPTED:
            raise NotEncryptedError
        self.crypto.smpAbort(appdata=appdata)

    def smpIsValid(self):
        return self.crypto.smp and self.crypto.smp.prog != crypt.SMPPROG_CHEATED

    def smpIsSuccess(self):
        return self.crypto.smp.prog == crypt.SMPPROG_SUCCEEDED \
                if self.crypto.smp else None

    def smpGotSecret(self, secret, question=None, appdata=None):
        if self.state != STATE_ENCRYPTED:
            raise NotEncryptedError
        self.crypto.smpSecret(secret, question=question, appdata=appdata)

    def smpInit(self, secret, question=None, appdata=None):
        if self.state != STATE_ENCRYPTED:
            raise NotEncryptedError
        self.crypto.smp = None
        self.crypto.smpSecret(secret, question=question, appdata=appdata)

    def handleQuery(self, message, appdata=None):
        if message.v2 and self.getPolicy('ALLOW_V2'):
            self.authStartV2(appdata=appdata)
        elif message.v1 and self.getPolicy('ALLOW_V1'):
            self.authStartV1(appdata=appdata)

    def authStartV1(self, appdata=None):
        raise NotImplementedError()

    def authStartV2(self, appdata=None):
        self.crypto.startAKE(appdata=appdata)

    def parse(self, message):
        otrTagPos = message.find(proto.OTRTAG)
        if otrTagPos == -1:
            if proto.MESSAGE_TAG_BASE in message:
                return proto.TaggedPlaintext.parse(message)
            else:
                return message

        indexBase = otrTagPos + len(proto.OTRTAG)
        compare = message[indexBase]

        if compare == b','[0]:
            message = self.fragmentAccumulate(message[indexBase:])
            if message is None:
                return None
            else:
                return self.parse(message)
        else:
            self.discardFragment()

        hasq = compare == b'?'[0]
        hasv = compare == b'v'[0]
        if hasq or hasv:
            hasv |= len(message) > indexBase+1 and \
                    message[indexBase+1] == b'v'[0]
            if hasv:
                end = message.find(b'?', indexBase+1)
            else:
                end = indexBase+1
            payload = message[indexBase:end]
            return proto.Query.parse(payload)

        if compare == b':'[0] and len(message) > indexBase + 4:
            infoTag = base64.b64decode(message[indexBase+1:indexBase+5])
            classInfo = struct.unpack(b'!HB', infoTag)
            cls = proto.messageClasses.get(classInfo, None)
            if cls is None:
                return message
            logging.debug('{user} got msg {typ!r}' \
                    .format(user=self.user.name, typ=cls))
            return cls.parsePayload(message[indexBase+5:])

        if message[indexBase:indexBase+7] == b' Error:':
            return proto.Error(message[indexBase+7:])

        return message

class Account(object):
    contextclass = Context
    def __init__(self, name, protocol, maxMessageSize, privkey=None):
        self.name = name
        self.privkey = privkey
        self.policy = {}
        self.protocol = protocol
        self.ctxs = {}
        self.maxMessageSize = maxMessageSize
        self.defaultQuery = b'?OTRv{versions}?\n{accountname} has requested ' \
                b'an Off-the-Record private conversation.  However, you ' \
                b'do not have a plugin to support that.\nSee '\
                b'http://otr.cypherpunks.ca/ for more information.';

    def __repr__(self):
        return '<{cls}(name={name!r})>'.format(cls=self.__class__.__name__,
                name=self.name)

    def getPrivkey(self, autogen=True):
        if self.privkey is None:
            self.privkey = self.loadPrivkey()
        if self.privkey is None:
            if autogen is True:
                self.privkey = crypt.DSAKey.generate()
                self.savePrivkey()
            else:
                raise LookupError
        return self.privkey

    def loadPrivkey(self):
        raise NotImplementedError

    def savePrivkey(self):
        raise NotImplementedError

    def saveTrusts(self):
        raise NotImplementedError

    def getContext(self, uid, newCtxCb=None):
        if uid not in self.ctxs:
            self.ctxs[uid] = self.contextclass(self, uid)
            if callable(newCtxCb):
                newCtxCb(self.ctxs[uid])
        return self.ctxs[uid]

    def getDefaultQueryMessage(self, policy):
        v  = b'2' if policy('ALLOW_V2') else b''
        return self.defaultQuery.format(accountname=self.name, versions=v)

class NotEncryptedError(RuntimeError):
    pass
class UnencryptedMessage(RuntimeError):
    pass
class ErrorReceived(RuntimeError):
    pass
