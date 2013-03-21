# some python3 compatibilty
from __future__ import print_function
from __future__ import unicode_literals

import unittest
import base64
from potr import proto
from potr import utils


class ProtoTest(unittest.TestCase):
    def testLongToBytes(self):
        self.assertEqual(b'\xde\xad\xbe\xef', 
                utils.long_to_bytes(0xdeadbeef))
        self.assertEqual(b'\0\0\0\0\0\0\xde\xad\xbe\xef', 
                utils.long_to_bytes(0xdeadbeef, 10))
        self.assertEqual(b'', utils.long_to_bytes(0x00))
        self.assertEqual(b'\0\0\0\0\0\0\0\0\0\0', utils.long_to_bytes(0x00, 10))

    def testPackData(self):
        self.assertEqual(b'\0\0\0\0', proto.pack_data(b''))
        self.assertEqual(b'\0\0\0\x0afoobarbazx', proto.pack_data(b'foobarbazx'))
        self.assertEqual(b'\0\1\0\0' + b'\xff' * 0x10000,
                proto.pack_data(b'\xff' * 0x10000))

    def testEncodeMpi(self):
        # small values
        self.assertEqual(b'\0\0\0\2\xff\0', proto.pack_mpi(65280))
        # the OTR protocol describes MPIs as carrying no leading zeros
        # so 0 itself should be encoded as the empty string
        self.assertEqual(b'\0\0\0\0', proto.pack_mpi(0))

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

    def queryBoth(self, suffix, vset):
        self.assertEqual(b'?OTR' + suffix, bytes(proto.Query(vset)))
        self.assertEqual(proto.Query(vset), proto.Query.parse(suffix))

    def taggedBoth(self, text, suffix, vset):
        self.assertEqual(text + suffix, bytes(proto.TaggedPlaintext(text, vset)))
        self.assertEqual(proto.TaggedPlaintext(text, vset),
                proto.TaggedPlaintext.parse(text + suffix))

    def testQuery(self):
        # these are "canonical" representations
        self.queryBoth(b'v?', set())
        self.queryBoth(b'v2?', set([2]))
        self.queryBoth(b'?v?', set([1]))
        self.queryBoth(b'?v2?', set([1, 2]))

        # these should be parsable but should not be produced
        self.assertEqual(proto.Query(set([1])), proto.Query.parse(b'?'))
        self.assertEqual(proto.Query(set([1])), proto.Query.parse(b'v1?'))
        self.assertEqual(proto.Query(set([1,2,3,8])), proto.Query.parse(b'v2831?'))
        self.assertEqual(proto.Query(set([0,1,2])), proto.Query.parse(b'?v20xy?'))


        # both version tags
        self.taggedBoth(b'',
                b'\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
                + b'\x20\x09\x20\x09\x20\x20\x09\x20'
                + b'\x20\x20\x09\x09\x20\x20\x09\x20',
                set([1,2]))
        # text + only v1 version tag
        self.taggedBoth(b'Hello World!\n',
                b'\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
                + b'\x20\x09\x20\x09\x20\x20\x09\x20',
                set([1]))
        # text + only v2 version tag
        self.taggedBoth(b'Foo.\n',
                b'\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
                + b'\x20\x20\x09\x09\x20\x20\x09\x20',
                set([2]))
        # only base tag, no version supported
        self.taggedBoth(b'',
                b'\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20',
                set([]))

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
