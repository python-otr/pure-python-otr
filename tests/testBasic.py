# some python3 compatibilty
from __future__ import print_function
from __future__ import unicode_literals

import unittest
import base64
from potr import proto


class ProtoTest(unittest.TestCase):
    def testPackData(self):
        self.assertEqual(b'\0\0\0\0', proto.pack_data(b''))
        self.assertEqual(b'\0\0\0\x0afoobarbazx', proto.pack_data(b'foobarbazx'))
        self.assertEqual(b'\0\1\0\0' + b'\xff' * 0x10000,
                proto.pack_data(b'\xff' * 0x10000))

    def testEncodeMpi(self):
        # small values
        self.assertEqual(b'\0\0\0\1\0', proto.pack_mpi(0))
        self.assertEqual(b'\0\0\0\2\xff\0', proto.pack_mpi(65280))
        # large values
        self.assertEqual(b'\0\0\1\1\1' + 256*b'\0', proto.pack_mpi(0x100**0x100))

    def testDecodeMpi(self):
        # small values
        self.assertEqual((0, b'foo'), proto.read_mpi(b'\0\0\0\0foo'))
        self.assertEqual((0, b''), proto.read_mpi(b'\0\0\0\1\0'))
        self.assertEqual((65280, b''), proto.read_mpi(b'\0\0\0\2\xff\0'))
        # large values
        self.assertEqual((0x100**0x100-1, b'\xff'),
                proto.read_mpi(b'\0\0\1\0'+257*b'\xff')) 

    def testUnpackData(self):
        encMsg = b'\0\0\0\1q\0\0\0\x0afoobarbazx'
        (decMsg, encMsg) = proto.read_data(encMsg)
        self.assertEqual(b'q', decMsg)
        (decMsg, encMsg) = proto.read_data(encMsg)
        self.assertEqual(b'foobarbazx', decMsg)
        self.assertEqual(b'', encMsg)

    def testQuery(self):
        self.assertEqual(b'?OTRv?', bytes(proto.Query(False, False)))
        self.assertEqual(b'?OTRv2?', bytes(proto.Query(False, True)))
        self.assertEqual(b'?OTR?v?', bytes(proto.Query(True, False)))
        self.assertEqual(b'?OTR?v2?', bytes(proto.Query(True, True)))

        self.assertEqual(proto.Query(False, False), proto.Query.parse(b'v?'))
        self.assertEqual(proto.Query(True, False), proto.Query.parse(b'?v?'))
        self.assertEqual(proto.Query(True, False), proto.Query.parse(b'?'))
        self.assertEqual(proto.Query(False, True), proto.Query.parse(b'v2?'))
        self.assertEqual(proto.Query(False, True), proto.Query.parse(b'v2831?'))
        self.assertEqual(proto.Query(False, False), proto.Query.parse(b'v1?'))
        self.assertEqual(proto.Query(True, True), proto.Query.parse(b'?v2?'))
        self.assertEqual(proto.Query(True, True), proto.Query.parse(b'?v20xy?'))

        # both version tags
        self.assertEqual(proto.TaggedPlaintext(b'', True, True),
                proto.TaggedPlaintext.parse(b'\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
                + b'\x20\x09\x20\x09\x20\x20\x09\x20'
                + b'\x20\x20\x09\x09\x20\x20\x09\x20'))
        # text + only v1 version tag
        self.assertEqual(proto.TaggedPlaintext(b'Hello World!\n', True, False),
                proto.TaggedPlaintext.parse(b'Hello World!\n'
                + b'\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
                + b'\x20\x09\x20\x09\x20\x20\x09\x20'))
        # text + only v2 version tag
        self.assertEqual(proto.TaggedPlaintext(b'Foo.\n', False, True),
                proto.TaggedPlaintext.parse(b'Foo.\n'
                + b'\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
                + b'\x20\x20\x09\x09\x20\x20\x09\x20'))
        # only base tag, no version supported
        self.assertEqual(proto.TaggedPlaintext(b'', False, False),
                proto.TaggedPlaintext.parse(b'\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'))

        # untagged
        self.assertRaises(TypeError,
                lambda: proto.TaggedPlaintext.parse(b'Foobarbaz?'))

        # only the version tag without base
        self.assertRaises(TypeError,
                lambda: proto.TaggedPlaintext.parse(b'Foobarbaz!'
                    + b'\x20\x09\x20\x09\x20\x20\x09\x20'))

    def testGenericMsg(self):
        msg = base64.b64encode(proto.pack_data(b'foo'))
        self.assertEqual(b'foo', proto.DHKey.parsePayload(msg).gy)
        self.assertEqual(b'?OTR:AAIK' + msg + b'.', bytes(proto.DHKey(b'foo')))

        msg = base64.b64encode(b'\x42\1\3\3\1\x08\6\4\2'
                + proto.pack_data(b'foo') + b'\0\0\0\0\xde\xad\xbe\xef'
                + proto.pack_data(b'encoded_dummy')
                + b'this is a dummy mac\0' + b'\0\0\0\0')
        pMsg = proto.DataMessage.parsePayload(msg)
        self.assertEqual(0x42, pMsg.flags)
        self.assertEqual(0x01030301, pMsg.skeyid)
        self.assertEqual(0x08060402, pMsg.rkeyid)
        self.assertEqual(b'foo', pMsg.dhy)
        self.assertEqual(b'\0\0\0\0\xde\xad\xbe\xef', pMsg.ctr)
        self.assertEqual(b'encoded_dummy', pMsg.encmsg)
        self.assertEqual(b'this is a dummy mac\0', pMsg.mac)
        self.assertEqual(b'', pMsg.oldmacs)
        self.assertEqual(b'?OTR:AAID' + msg + b'.',
            bytes(proto.DataMessage(0x42, 0x01030301, 0x08060402, b'foo',
                b'\0\0\0\0\xde\xad\xbe\xef', b'encoded_dummy',
                b'this is a dummy mac\0', b'')))

    def testGenericTLV(self):
        testtlvs = [
                (proto.DisconnectTLV(), b'\0\1\0\0'),
                (proto.SMP1TLV([1, 2, 3, 4, 5, 6]),
                    b'\0\2\0\x22\0\0\0\6\0\0\0\1\1\0\0\0\1\2\0\0\0\1\3\0\0\0\1\4\0\0\0\1\5\0\0\0\1\6'),
                (proto.SMPABORTTLV(), b'\0\6\0\0')
                ]

        for tlv, data in testtlvs:
            self.assertEqual(tlv, proto.TLV.parse(data)[0])
            self.assertEqual(data, bytes(tlv))

        tlvs, datas = tuple(zip(*testtlvs))
        self.assertEqual(list(tlvs), proto.TLV.parse(b''.join(datas)))

        self.assertRaises(TypeError, lambda: proto.TLV.parse(b'\0\1\0\1x'))

if __name__ == '__main__':
    unittest.main()
