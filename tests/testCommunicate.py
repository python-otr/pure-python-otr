import os
import pickle
import sys

import unittest

import otr
from potr import context

MMS = 30
PROTO = 'test'

PNAME = 'P-pureotr'
CNAME = 'C-libotr'


#############################################################################
#
#   pure-otr infrastructure
#
#############################################################################

class TestContext(context.Context):
    def getPolicy(self, key):
        return self.user.policy[key]

    def inject(self, msg, appdata=None):
        appdata.csend(str(msg))

class TestAccount(context.Account):
    contextclass = TestContext
    def __init__(self, name, proto, mms, policy):
        super(TestAccount, self).__init__(name, proto, mms)
        self.policy = policy
    def loadPrivkey(self):
        try:
            with open(os.path.join(sys.path[0], 'pTest.key'), 'r') as keyFile:
                return pickle.load(keyFile)
        except IOError, e:
            return None

    def savePrivkey(self):
        pass

#############################################################################
#
#   libotr infrastructure
#
#############################################################################

class COps:
    def __init__(self, test, policy):
        self.test = test
        self.dpolicy = policy
        self.cSecState = 0
        self.cSecTrust = False

    def policy(self, opdata=None, context=None):
        val = int(self.dpolicy['ALLOW_V1'])
        val |= int(self.dpolicy['ALLOW_V2']) << 1
        val |= int(self.dpolicy['REQUIRE_ENCRYPTION']) << 2
        val |= int(self.dpolicy['SEND_TAG']) << 3
        val |= int(self.dpolicy['WHITESPACE_START_AKE']) << 4
        val |= int(self.dpolicy['ERROR_START_AKE']) << 5
        return val

    def create_privkey(self, opdata=None, accountname=None, protocol=None):
        pass # ignore

    def is_logged_in(self, opdata=None, accountname=None, protocol=None,
            recipient=None):
        return True
    
    def inject_message(self, opdata=None, accountname=None, protocol=None,
            recipient=None, message=None):
        opdata.psend(message)

    def notify(sef, opdata=None, level=None, accountname=None, protocol=None,
            username=None, title=None, primary=None, secondary=None):
        print '\nOTR notify: %r' % (title, primary, secondar)
        pass # ignore

    def display_otr_message(self, opdata=None, accountname=None,
            protocol=None, username=None, msg=None):
        return 1

    def update_context_list(self, opdata=None):
        pass

    def protocol_name(self, opdata=None, protocol=None):
        return PROTO

    def new_fingerprint(self, opdata=None, userstate=None, accountname=None,
            protocol=None, username=None, fingerprint=None):
        cFpReceived = otr.otrl_privkey_hash_to_human(fingerprint)

    def write_fingerprints(self, opdata=None):
        pass # ignore

    def gone_secure(self, opdata=None, context=None):
        trust = context.active_fingerprint.trust
        self.cSecState = 1
        if trust:
           self.cSecTrust = True
        else:
           self.cSecTrust = False

    def gone_insecure(self, opdata=None, context=None):
        self.cSecState = 2

    def still_secure(self, opdata=None, context=None, is_reply=0):
        pass # ignore

    def log_message(self, opdata=None, message=None):
        print '\nOTR LOG: %r' % message
        pass # ignore

    def max_message_size(self, opdata=None, context=None):
        return MMS

    def account_name(self, opdata=None, account=None, context=None):
        return CNAME




class TestCommunicate(unittest.TestCase):
    def setUp(self):
        self.pQueue = []
        self.cQueue = []

        self.cUserState = otr.otrl_userstate_create()

    def createWithPolicies(self, ppol, cpol=None):
        if cpol is None:
            cpol = ppol
        self.pAccount = TestAccount(PNAME, PROTO, MMS, ppol)
        self.pCtx = self.pAccount.getContext(CNAME)
        self.cops = COps(self, cpol)
        otr.otrl_privkey_read(self.cUserState, "cTest.key")


#############################################################################
#
#   Actual tests
#
#############################################################################

    def testAutoFromP(self):
        self.createWithPolicies({
                    'ALLOW_V1':False,
                    'ALLOW_V2':True,
                    'REQUIRE_ENCRYPTION':False,
                    'SEND_TAG':True,
                    'WHITESPACE_START_AKE':True,
                    'ERROR_START_AKE':True,
                })

        self.psend(self.otrcsend('hello!'))
        self.assertEqual(('hello!', []),
                self.otrpparse(self.pCtx, self.prcv()))

        # no more messages to process:
        self.assertEqual((None, None, None), self.process(self.pCtx, self.cUserState))
        # went encrypted
        self.assertEqual(context.STATE_ENCRYPTED, self.cops.cSecState)
        self.assertEqual(context.STATE_ENCRYPTED, self.pCtx.state)

        # is untrusted
        self.assertFalse(self.cops.cSecTrust)
        self.assertFalse(self.pCtx.getCurrentTrust()) 

    def testAutoFromC(self):
        self.createWithPolicies({
                    'ALLOW_V1':False,
                    'ALLOW_V2':True,
                    'REQUIRE_ENCRYPTION':False,
                    'SEND_TAG':True,
                    'WHITESPACE_START_AKE':True,
                    'ERROR_START_AKE':True,
                })

        self.otrpsend(self.pCtx, 'hello!', context.FRAGMENT_SEND_ALL)
        self.assertEqual((False, 'hello!', None), self.otrcparse(self.crcv()))

        # no more messages to process:
        self.assertEqual((None, None, None), self.process(self.pCtx, self.cUserState))
        # went encrypted
        self.assertEqual(context.STATE_ENCRYPTED, self.cops.cSecState)
        self.assertEqual(context.STATE_ENCRYPTED, self.pCtx.state)

        # is untrusted
        self.assertFalse(self.cops.cSecTrust)
        self.assertFalse(self.pCtx.getCurrentTrust()) 

    def testNothingFromP(self):
        self.createWithPolicies({
                    'ALLOW_V1':True,
                    'ALLOW_V2':True,
                    'REQUIRE_ENCRYPTION':False,
                    'SEND_TAG':False,
                    'WHITESPACE_START_AKE':False,
                    'ERROR_START_AKE':False,
                })

        origMsg = 'hello!'*100

        # no fragmentation, message unchanged
        msg = self.otrpsend(self.pCtx, origMsg)
        self.assertEqual(origMsg, msg)
        self.csend(msg)

        self.assertEqual((False, origMsg, None), self.otrcparse(self.crcv()))

        # no more messages to process:
        self.assertEqual((None, None, None), self.process(self.pCtx, self.cUserState))
        # went encrypted
        self.assertEqual(context.STATE_PLAINTEXT, self.cops.cSecState)
        self.assertEqual(context.STATE_PLAINTEXT, self.pCtx.state)

        # is untrusted
        self.assertFalse(self.cops.cSecTrust)
        self.assertFalse(self.pCtx.getCurrentTrust()) 

    def testNothingFromC(self):
        self.createWithPolicies({
                    'ALLOW_V1':True,
                    'ALLOW_V2':True,
                    'REQUIRE_ENCRYPTION':False,
                    'SEND_TAG':False,
                    'WHITESPACE_START_AKE':False,
                    'ERROR_START_AKE':False,
                })

        origMsg = 'hello!'*100

        # no fragmentation, message unchanged
        msg = self.otrcsend(origMsg)
        self.assertEqual(origMsg, msg)
        self.psend(msg)

        self.assertEqual((origMsg, []), self.otrpparse(self.pCtx, self.prcv()))

        # no more messages to process:
        self.assertEqual((None, None, None), self.process(self.pCtx, self.cUserState))
        # went encrypted
        self.assertEqual(context.STATE_PLAINTEXT, self.cops.cSecState)
        self.assertEqual(context.STATE_PLAINTEXT, self.pCtx.state)

        # is untrusted
        self.assertFalse(self.cops.cSecTrust)
        self.assertFalse(self.pCtx.getCurrentTrust()) 

#############################################################################
#
#   Message helpers
#
#############################################################################

    def otrcparse(self, msg):
        return otr.otrl_message_receiving(self.cUserState, (self.cops, self),
            CNAME, PROTO, PNAME, msg)

    def otrcsend(self, msg):
        return otr.otrl_message_sending(self.cUserState, (self.cops, self),
            CNAME, PROTO, PNAME, msg, None)

    def otrpparse(self, ctx, msg):
        return ctx.receiveMessage(msg, appdata=self)

    def otrpsend(self, ctx, msg, fragment=context.FRAGMENT_SEND_ALL_BUT_FIRST):
        return ctx.sendMessage(fragment, msg, appdata=self)


#############################################################################
#
#   Message queues
#
#############################################################################



    def csend(self, msg):
        self.cQueue.append(msg)

    def crcv(self):
        return self.cQueue.pop(0)

    def psend(self, msg):
        self.pQueue.append(msg)

    def prcv(self):
        return self.pQueue.pop(0)

    def process(self, pCtx, cUserState):
        while len(self.cQueue) > 0 or len(self.pQueue) > 0:
            if self.pQueue:
                txt, tlvs = self.otrpparse(self.pCtx, self.prcv())
                if txt:
                    return (False, txt, tlvs)
            if self.cQueue:
                is_internal, txt, tlvs = self.otrcparse(self.crcv())
                if not is_internal and txt:
                    return (True, txt, tlvs)
        return None, None, None
