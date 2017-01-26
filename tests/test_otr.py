# pylint: disable=abstract-method
# pylint: disable=invalid-name
# pylint: disable=missing-docstring

from __future__ import unicode_literals

import unittest

import potr

class PostOffice(object):

    def __init__(self):
        self.mailboxes = {}

    def add_mailbox(self, address, f):
        self.mailboxes[address] = f

    def send(self, address, message):
        self.mailboxes[address](message)

class TestContext(potr.context.Context):
    def getPolicy(self, key):
        return True

    def inject(self, msg, appdata=None):
        self.user.post_office.send(self.peer, msg)

class TestAccount(potr.context.Account):
    contextclass = TestContext

    def __init__(self, name, post_office):
        self.post_office = post_office

        super(TestAccount, self).__init__(name, 'test_protocol', 415)

    def loadPrivkey(self):
        pass

    def savePrivkey(self):
        pass

class OtrTest(unittest.TestCase):

    def test_conversation(self):
        post_office = PostOffice()

        alice = TestAccount('alice', post_office)
        alice_bob = alice.getContext('bob')

        bob = TestAccount('bob', post_office)
        bob_alice = bob.getContext('alice')

        alice_received = []
        def to_alice(message):
            msg, _ = alice_bob.receiveMessage(message)
            if msg:
                alice_received.append(msg)

        post_office.add_mailbox('alice', to_alice)

        bob_received = []
        def to_bob(message):
            msg, _ = bob_alice.receiveMessage(message)
            if msg:
                bob_received.append(msg)

        post_office.add_mailbox('bob', to_bob)

        # bob never receives this because require_encryption is true
        message1 = alice_bob.sendMessage(
            potr.context.FRAGMENT_SEND_ALL, b'we need to talk')

        post_office.send('bob', message1)

        alice_bob.sendMessage(
            potr.context.FRAGMENT_SEND_ALL, b'hello')

        self.assertEqual(bob_received[0], b'hello')

        bob_alice.sendMessage(
            potr.context.FRAGMENT_SEND_ALL, b'how are you?')

        self.assertEqual(alice_received[0], b'how are you?')
