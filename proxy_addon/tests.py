import unittest

from hippolyzer.lib.base.datatypes import UUID
from hippolyzer.lib.base.message.message import Block, Message
from hippolyzer.lib.base.network.transport import Direction, UDPPacket
from hippolyzer.lib.proxy.test_utils import BaseProxyTest
from hippolyzer.lib.proxy.addons import AddonManager

from fake_lludp_encryption import FakeLLUDPEncryptionAddon


class LLUDPEncryptionTests(BaseProxyTest):
    def setUp(self):
        super().setUp()
        self.session.agent_id = UUID("89556747-24cb-43ed-920b-47caed15465f")
        self.session.id = UUID("89556747-24cb-43ed-920b-47caed15465f")
        self.session.circuit_code = 2
        self.addon = FakeLLUDPEncryptionAddon()
        AddonManager.init([], self.session_manager, [self.addon])
        self._setup_default_circuit()

    def _make_example_packet(self):
        msg = Message(
            "UseCircuitCode",
            Block("CircuitCode", Code=self.circuit_code, SessionID=self.session.id,
                  ID=self.session.agent_id),
            packet_id=1,
            direction=Direction.IN,
        )
        return self._msg_to_packet(msg, src=self.region_addr, dst=self.client_addr)

    async def test_message_round_trips(self):
        packet = self._make_example_packet()
        unencrypted = packet.data
        self.protocol.handle_proxied_packet(packet)
        # The proxy should encrypt the packet on the way in
        encrypted = self.transport.packets[-1][0]
        # Encrypted flag should be set, v1 encryption with no extra field
        self.assertEqual(b"\x08\x01", encrypted[0:2])
        # First 4 bytes of the nonce should be the unencrypted packet ID
        self.assertEqual(unencrypted[1:5], encrypted[2:6])
        self.assertNotEqual(encrypted, unencrypted)

        # Take the encrypted message and send it back out.
        self.protocol.handle_proxied_packet(UDPPacket(
            src_addr=self.client_addr,
            dst_addr=self.region_addr,
            data=encrypted,
            direction=Direction.OUT,
        ))
        # Should have byte-for-byte equality with what we first sent
        self.assertEqual(unencrypted, self.transport.packets[-1][0])
        self.assertEqual(2, len(self.transport.packets))

    async def test_tamper_messages_rejected(self):
        packet = self._make_example_packet()
        self.protocol.handle_proxied_packet(packet)
        encrypted = bytearray(self.transport.packets[-1][0])
        # Flip the last byte, should cause a tag mismatch and refuse to send.
        encrypted[-1] = (~encrypted[-1]) & 0xFF

        self.protocol.handle_proxied_packet(UDPPacket(
            src_addr=self.client_addr,
            dst_addr=self.region_addr,
            data=encrypted,
            direction=Direction.OUT,
        ))
        # Only first handled packet actually sent
        self.assertEqual(1, len(self.transport.packets))


if __name__ == "__main__":
    unittest.main()
