import unittest
import base64
from potr import proto


class ProtoTest(unittest.TestCase):
    def testPackData(self):
        self.assertEqual('\0\0\0\0', proto.pack_data(''))
        self.assertEqual('\0\0\0\x0afoobarbazx', proto.pack_data('foobarbazx'))
        self.assertEqual('\0\1\0\0' + '\xff' * 0x10000,
                proto.pack_data('\xff' * 0x10000))

    def testEncodeMpi(self):
        # small values
        self.assertEqual('\0\0\0\1\0', proto.pack_mpi(0))
        self.assertEqual('\0\0\0\2\xff\0', proto.pack_mpi(65280))
        # large values
        self.assertEqual('\0\0\1\1\1' + 256*'\0', proto.pack_mpi(0x100**0x100))

    def testDecodeMpi(self):
        # small values
        self.assertEqual((0, 'foo'), proto.read_mpi('\0\0\0\0foo'))
        self.assertEqual((0, ''), proto.read_mpi('\0\0\0\1\0'))
        self.assertEqual((65280, ''), proto.read_mpi('\0\0\0\2\xff\0'))
        # large values
        self.assertEqual((0x100**0x100-1, '\xff'),
                proto.read_mpi('\0\0\1\0'+257*'\xff')) 

    def testUnpackData(self):
        encMsg = '\0\0\0\1q\0\0\0\x0afoobarbazx'
        (decMsg, encMsg) = proto.read_data(encMsg)
        self.assertEqual('q', decMsg)
        (decMsg, encMsg) = proto.read_data(encMsg)
        self.assertEqual('foobarbazx', decMsg)
        self.assertEqual('', encMsg)

    def testQuery(self):
        self.assertEqual('?OTRv?', str(proto.Query(False, False)))
        self.assertEqual('?OTRv2?', str(proto.Query(False, True)))
        self.assertEqual('?OTR?v?', str(proto.Query(True, False)))
        self.assertEqual('?OTR?v2?', str(proto.Query(True, True)))

        self.assertEqual(proto.Query(False, False), proto.Query.parse('v?'))
        self.assertEqual(proto.Query(True, False), proto.Query.parse('?v?'))
        self.assertEqual(proto.Query(True, False), proto.Query.parse('?'))
        self.assertEqual(proto.Query(False, True), proto.Query.parse('v2?'))
        self.assertEqual(proto.Query(False, True), proto.Query.parse('v2831?'))
        self.assertEqual(proto.Query(False, False), proto.Query.parse('v1?'))
        self.assertEqual(proto.Query(True, True), proto.Query.parse('?v2?'))
        self.assertEqual(proto.Query(True, True), proto.Query.parse('?v20xy?'))

        # both version tags
        self.assertEqual(proto.TaggedPlaintext('', True, True),
                proto.TaggedPlaintext.parse('\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
                + '\x20\x09\x20\x09\x20\x20\x09\x20'
                + '\x20\x20\x09\x09\x20\x20\x09\x20'))
        # text + only v1 version tag
        self.assertEqual(proto.TaggedPlaintext('Hello World!\n', True, False),
                proto.TaggedPlaintext.parse('Hello World!\n'
                + '\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
                + '\x20\x09\x20\x09\x20\x20\x09\x20'))
        # text + only v2 version tag
        self.assertEqual(proto.TaggedPlaintext('Foo.\n', False, True),
                proto.TaggedPlaintext.parse('Foo.\n'
                + '\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'
                + '\x20\x20\x09\x09\x20\x20\x09\x20'))
        # only base tag, no version supported
        self.assertEqual(proto.TaggedPlaintext('', False, False),
                proto.TaggedPlaintext.parse('\x20\x09\x20\x20\x09\x09\x09\x09\x20\x09\x20\x09\x20\x09\x20\x20'))

        # untagged
        with self.assertRaises(TypeError):
            proto.TaggedPlaintext.parse('Foobarbaz?')

        # only the version tag without base
        with self.assertRaises(TypeError):
            proto.TaggedPlaintext.parse('Foobarbaz!'
                    + '\x20\x09\x20\x09\x20\x20\x09\x20')

    def testGenericMsg(self):
        msg = base64.b64encode(proto.pack_data('foo'))
        self.assertEquals('foo', proto.DHKey.parsePayload(msg).gy)
        self.assertEquals('?OTR:AAIK%s.' % msg, str(proto.DHKey('foo')))

        msg = base64.b64encode('\x42\1\3\3\1\x08\6\4\2'
                + proto.pack_data('foo') + '\0\0\0\0\xde\xad\xbe\xef'
                + proto.pack_data('encoded_dummy')
                + 'this is a dummy mac\0' + '\0\0\0\0')
        pMsg = proto.DataMessage.parsePayload(msg)
        self.assertEquals(0x42, pMsg.flags)
        self.assertEquals(0x01030301, pMsg.skeyid)
        self.assertEquals(0x08060402, pMsg.rkeyid)
        self.assertEquals('foo', pMsg.dhy)
        self.assertEquals('\0\0\0\0\xde\xad\xbe\xef', pMsg.ctr)
        self.assertEquals('encoded_dummy', pMsg.encmsg)
        self.assertEquals('this is a dummy mac\0', pMsg.mac)
        self.assertEquals('', pMsg.oldmacs)
        self.assertEquals('?OTR:AAID%s.' % msg,
            str(proto.DataMessage(0x42, 0x01030301, 0x08060402, 'foo',
                '\0\0\0\0\xde\xad\xbe\xef', 'encoded_dummy',
                'this is a dummy mac\0', '')))

    def testGenericTLV(self):
        testtlvs = [
                (proto.DisconnectTLV(), '\0\1\0\0'),
                (proto.SMP1TLV([1, 2, 3, 4, 5, 6]),
                    '\0\2\0\x22\0\0\0\6\0\0\0\1\1\0\0\0\1\2\0\0\0\1\3\0\0\0\1\4\0\0\0\1\5\0\0\0\1\6'),
                (proto.SMPABORTTLV(), '\0\6\0\0')
                ]

        for tlv, data in testtlvs:
            self.assertEquals(tlv, proto.TLV.parse(data)[0])
            self.assertEquals(data, str(data))

        tlvs, datas = tuple(zip(*testtlvs))
        self.assertEquals(list(tlvs), proto.TLV.parse(''.join(datas)))

        with self.assertRaises(TypeError):
            # DisconnectTLV must not contain data
            proto.TLV.parse('\0\1\0\1x')

        
