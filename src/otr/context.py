#!/usr/bin/python2

import base64
import logging
import struct

import crypt
import proto

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
            'inject', 'trust']

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

    def policyOtrEnabled(self):
        return self.getPolicy('ALLOW_V1') or self.getPolicy('ALLOW_V2')

    def discardFragment(self):
        self.fragmentInfo = (0, 0)
        self.fragment = []

    def fragmentAccumulate(self, message):
        '''Accumulate a fragmented message. Returns None if the fragment is
        to be ignored, returns a string if the message is ready for further
        processing'''

        params = message.split(',')
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
            assembled = ''.join(self.fragment)
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
                        'You sent encrypted to {}, who wasn\'t expecting it.'
                            .format(self.user.name)), appdata=appdata)
                if ignore:
                    return IGN
                raise NotEncryptedError(EXC_UNREADABLE_MESSAGE)

            try:
                plaintext, tlvs = self.crypto.handleDataMessage(message)
                self.processTLVs(tlvs, appdata=appdata)
                if plaintext and self.lastSend < time() - HEARTBEAT_INTERVAL:
                    self.sendInternal('', appdata=appdata)
                return plaintext or None, tlvs
            except crypt.InvalidParameterError, e:
                if ignore:
                    return IGN
                logging.exception('decryption failed')
                raise e
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
            self.sendFragmented(FRAGMENT_SEND_ALL, str(msg), appdata=appdata)

    def sendMessage(self, sendPolicy, msg, flags=0, tlvs=[], appdata=None):
        if self.policyOtrEnabled():
            self.lastSend = time()
            msg = str(self.processOutgoingMessage(msg, flags, tlvs))
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
            self.sendInternal('', tlvs=[proto.DisconnectTLV()], appdata=appdata)
            self.setState(STATE_PLAINTEXT)
            self.crypto.finished()
        else:
            self.setState(STATE_PLAINTEXT)

    def setState(self, newstate):
        self.state = newstate

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
                fragments[fi] = '?OTR,{},{},{},'.format(fi+1, fc, fragments[fi])

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
            logging.info('got unhandled tlv: {!r}'.format(tlv))

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

        if compare == ',':
            message = self.fragmentAccumulate(message[indexBase:])
            if message is None:
                return None
            else:
                return self.parse(message)
        else:
            self.discardFragment()

        hasq = compare == '?'
        hasv = compare == 'v'
        if hasq or hasv:
            hasv |= len(message) > indexBase+1 and message[indexBase+1] == 'v'
            if hasv:
                end = message.find('?', indexBase+1)
            else:
                end = indexBase+1
            payload = message[indexBase:end]
            return proto.Query.parse(payload)

        if compare == ':' and len(message) > indexBase + 4:
            infoTag = base64.b64decode(message[indexBase+1:indexBase+5])
            classInfo = struct.unpack('!HB', infoTag)
            cls = proto.messageClasses.get(classInfo, None)
            if cls is None:
                return message
            logging.debug('{} got msg {!r}'.format(self.user.name, cls))
            return cls.parsePayload(message[indexBase+5:])

        if message[indexBase:indexBase+7] == ' Error:':
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
        self.defaultQuery = '?OTRv{versions}?\n{accountname} has requested ' \
                'an Off-the-Record private conversation.  However, you ' \
                'do not have a plugin to support that.\nSee '\
                'http://otr.cypherpunks.ca/ for more information.';

    def __repr__(self):
        return '<{cls}(name={name!r})>'.format(cls=self.__class__.__name__,
                name=self.name)

    def getPrivkey(self):
        if self.privkey is None:
            self.privkey = self.loadPrivkey()
        if self.privkey is None:
            self.privkey = crypt.DSAKey.generate()
            self.savePrivkey()
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
        v  = '2' if policy('ALLOW_V2') else ''
        return self.defaultQuery.format(accountname=self.name, versions=v)

class NotEncryptedError(RuntimeError):
    pass
class UnencryptedMessage(RuntimeError):
    pass
class ErrorReceived(RuntimeError):
    pass
