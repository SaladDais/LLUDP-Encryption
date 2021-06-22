# Copyme (C) 2021 Salad Dais
#
# ISC, Apache v2, or public domain, at your preference.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Addon for Hippolyzer to pretend that regions support UDP transport encryption

Useful for testing a client's implementation of UDP transport encryption
without a working server implementation.

Pretends all regions support encryption for now.
"""

import dataclasses
import enum
import hmac
import logging
import secrets
import socket
import struct
import xmlrpc.client
from typing import *

import cryptography.hazmat.primitives.ciphers.aead
from cryptography.exceptions import InvalidTag

from hippolyzer.lib.base import serialization as se
from hippolyzer.lib.base.datatypes import UUID
from hippolyzer.lib.base.message.llsd_msg_serializer import LLSDMessageSerializer
from hippolyzer.lib.base.message.message import Message
from hippolyzer.lib.proxy.addon_utils import BaseAddon
from hippolyzer.lib.base.network.transport import UDPPacket, ADDR_TUPLE, AbstractUDPTransport
from hippolyzer.lib.proxy.circuit import ProxiedCircuit
from hippolyzer.lib.proxy.http_flow import HippoHTTPFlow
from hippolyzer.lib.proxy.region import ProxiedRegion
from hippolyzer.lib.proxy.sessions import SessionManager, Session

LOG = logging.getLogger(__name__)


class EncryptedSendFlags(enum.IntEnum):
    """Send flags that are respected by encrypted message wrappers. Only one."""
    # Lower bits of LLUDP flags byte were unused so I picked this arbitrarily.
    ENCRYPTED = 0x08


class EncryptionVersion(enum.IntEnum):
    V1 = 1


@dataclasses.dataclass
class V1Payload:
    # By convention the first 4 bytes of `nonce_bytes` are the packet ID,
    # the other 8 bytes are from a PRNG.
    nonce: bytes = se.dataclass_field(se.BytesFixed(12))
    # Circuit code for the circuit this packet is being sent over, will be used
    # to look up the shared secret used to encrypt the packet. Accordingly, anonymous
    # Circuits with no circuit code may not be encrypted, but these basically don't exist
    # as far as viewers are concerned.
    circuit_code: int = se.dataclass_field(se.U32)
    # Everything left is the ciphertext (with appended authentication tag)
    ciphertext: bytes = se.dataclass_field(se.BytesGreedy())


@dataclasses.dataclass
class EncryptedMessageWrapper:
    send_flags: EncryptedSendFlags = se.dataclass_field(se.IntEnum(EncryptedSendFlags, se.U8))
    # Tagged union with encryption version and payload, only V1 for now.
    payload: Tuple[EncryptionVersion, Union[V1Payload]] = se.dataclass_field(
        se.EnumSwitch(se.IntEnum(EncryptionVersion, se.U8), {
            EncryptionVersion.V1: se.Dataclass(V1Payload),
        }),
    )


ENCRYPTED_MESSAGE_SPEC = se.Dataclass(EncryptedMessageWrapper)


def _get_circuit_key(session_id: UUID, sim_addr: ADDR_TUPLE) -> bytes:
    """
    Get the 256-bit encryption key to use for a given circuit

    `HMAC_SHA256(session_id_bytes, sim IP || sim port bytes)` (all network-endian)
    """
    ip, port = sim_addr
    h = hmac.new(session_id.bytes, None, "sha256")
    h.update(socket.inet_aton(ip) + struct.pack("!H", port))
    return h.digest()


class EncryptingTransportWrapper(AbstractUDPTransport):
    def __init__(self, session: Session, far_addr: ADDR_TUPLE, base_transport: AbstractUDPTransport):
        self.circuit_code = session.circuit_code
        self.encryption_key = _get_circuit_key(session.id, far_addr)
        self.base_transport = base_transport
        self.is_encrypted = False

    def send_packet(self, packet: UDPPacket) -> None:
        # Don't touch outgoing packets, we're wrapping a connection
        # to a server that doesn't know about encryption.
        if packet.outgoing or not self.is_encrypted:
            self.base_transport.send_packet(packet)
            return
        # Incoming packets need to be encrypted!
        # 12-byte nonce will be the 4 byte packet ID + 8 random bytes
        nonce = packet.data[1:5] + secrets.token_bytes(8)
        aes = cryptography.hazmat.primitives.ciphers.aead.AESGCM(self.encryption_key)
        encrypted = aes.encrypt(nonce, packet.data, None)
        payload = V1Payload(
            nonce=nonce,
            circuit_code=self.circuit_code,
            ciphertext=encrypted,
        )
        writer = se.BufferWriter("!")
        writer.write(ENCRYPTED_MESSAGE_SPEC, EncryptedMessageWrapper(
            send_flags=EncryptedSendFlags.ENCRYPTED,
            payload=(EncryptionVersion.V1, payload),
        ))
        packet.data = writer.buffer
        self.base_transport.send_packet(packet)

    def close(self) -> None:
        self.base_transport.close()


class FakeLLUDPEncryptionAddon(BaseAddon):
    # Flip to False if you want to test that regions that don't
    # support encryption will be handled correctly by the viewer
    ALL_REGIONS_SUPPORT_ENCRYPTION = True

    def __init__(self):
        self.llsd_message_serializer = LLSDMessageSerializer()

    def handle_init(self, session_manager: SessionManager):
        # Wrap any existing circuit transports
        for session in session_manager.sessions:
            for region in session.regions:
                if not region.circuit:
                    continue
                transport = region.circuit.transport
                if not isinstance(transport, EncryptingTransportWrapper):
                    transport = EncryptingTransportWrapper(session, region.circuit_addr, transport)
                    # Reloading, so just assume the circuit was encrypted if the addr supported it.
                    if self._addr_supports_encryption(region.circuit_addr):
                        transport.is_encrypted = True
                    region.circuit.transport = transport

    def _addr_supports_encryption(self, addr: ADDR_TUPLE):
        if self.ALL_REGIONS_SUPPORT_ENCRYPTION:
            return True
        # Pretend all sims with ports not divisible by 3 support encryption
        return addr[1] % 3 != 0

    def handle_unload(self, session_manager: SessionManager):
        # Wrap any existing circuit transports
        for session in session_manager.sessions:
            for region in session.regions:
                if not region.circuit:
                    continue
                transport = region.circuit.transport
                if isinstance(transport, EncryptingTransportWrapper):
                    region.circuit.transport = transport.base_transport

    def handle_circuit_created(self, session: Session, region: ProxiedRegion):
        # Swap out the newly created circuit's transport with one that will
        # automatically encrypt packets on the way to the client
        transport = region.circuit.transport
        transport = EncryptingTransportWrapper(session, region.circuit_addr, transport)
        region.circuit.transport = transport
        return True

    def handle_proxied_packet(self, session_manager: SessionManager, packet: UDPPacket,
                              _session: Optional[Session], _region: Optional[ProxiedRegion]):
        if not packet.outgoing:
            return
        # Not encrypted, take the normal path.
        if not packet.data[0] & EncryptedSendFlags.ENCRYPTED:
            return
        if not self._addr_supports_encryption(packet.far_addr):
            logging.warning(f"Received encrypted packet on unencrypted circuit for {packet.far_addr}")

        reader = se.BufferReader("!", packet.data)
        unpacked: EncryptedMessageWrapper = reader.read(ENCRYPTED_MESSAGE_SPEC)
        version, payload = unpacked.payload
        if version != EncryptionVersion.V1:
            logging.error(f"Unknown encryption version, not sending! {version!r}")
            return True
        key_session = self._circuit_code_to_session(session_manager, payload.circuit_code)
        if key_session is None:
            logging.error(f"Couldn't find session for circuit code {payload.circuit_code}")
            return True

        key_region = key_session.region_by_circuit_addr(packet.far_addr)
        key_region_circuit: Optional[ProxiedCircuit] = key_region and key_region.circuit
        if key_region_circuit:
            # We wrap all circuit transports so we know there will be an encryption key.
            transport: Optional[EncryptingTransportWrapper] = key_region_circuit.transport
            key = transport.encryption_key
        else:
            # Destination address doesn't have a circuit yet, no cached key. Derive it.
            # Will be the case before our initial UseCircuitCode has been handled.
            key = _get_circuit_key(key_session.id, packet.far_addr)

        aes = cryptography.hazmat.primitives.ciphers.aead.AESGCM(key)
        try:
            # This is a `bytearray` and aes.decrypt wants a `bytes`
            ciphertext = bytes(payload.ciphertext)
            decrypted = bytearray(aes.decrypt(payload.nonce, ciphertext, None))
        except InvalidTag:
            logging.error(f"Invalid tag on encrypted message, not sending! {unpacked!r}")
            return True

        packet.meta["encrypted"] = True
        packet.data = decrypted

    def _circuit_code_to_session(self, session_manager: SessionManager, circuit_code: int) -> Optional[Session]:
        # This would be a lookup in the circuit code -> session ID map in indra's newsim
        for session in session_manager.sessions:
            if session.circuit_code == circuit_code:
                return session
        return None

    def handle_lludp_message(self, session: Session, region: ProxiedRegion, message: Message):
        # Sending an encrypted UseCircuitCode switches the circuit to encrypted mode
        if message.name == "UseCircuitCode":
            is_encrypted = message.meta.get("encrypted", False)
            encryption_supported = self._addr_supports_encryption(region.circuit_addr)
            will_encrypt = is_encrypted and encryption_supported
            # Should use encryption if it's supported, not use it if it's not.
            logging.info(f"Opening circuit for {region}, {will_encrypt=}")
            if is_encrypted != encryption_supported:
                logging.error(f"Encryption mismatch on {region}! "
                              f"{is_encrypted=} != {encryption_supported=}")
            if will_encrypt:
                transport: Optional[EncryptingTransportWrapper] = region.circuit.transport
                transport.is_encrypted = True

    def handle_eq_event(self, session: Session, region: ProxiedRegion, event: dict):
        # Tell the viewer if the regions they're being asked to connect to support encryption
        add_encryption_field = False
        if event["message"] in ("EnableSimulator", "TeleportFinish"):
            msg = self.llsd_message_serializer.deserialize(event)
            sim_addr = None
            if event["message"] == "EnableSimulator":
                sim_addr = msg["SimulatorInfo"]["IP"], msg["SimulatorInfo"]["Port"]
            elif event["message"] == "TeleportFinish":
                sim_addr = msg["Info"]["SimIP"], msg["Info"]["SimPort"]
            add_encryption_field = self._addr_supports_encryption(sim_addr)
        if add_encryption_field:
            event["body"]["CircuitEncryptionInfo"] = [{"SupportedVersions": 1}]

    def handle_http_response(self, session_manager: SessionManager, flow: HippoHTTPFlow):
        if flow.cap_data.cap_name == "LoginRequest":
            # Tell whether the viewer the start region supports encryption
            resp, method_name = xmlrpc.client.loads(flow.response.content)  # type: ignore
            body = resp[0]
            sim_addr = body["sim_ip"], body["sim_port"]
            if self._addr_supports_encryption(sim_addr):
                body["supported_encryption_versions"] = "1"
            flow.response.text = xmlrpc.client.dumps(resp, methodname=method_name, allow_none=True)


addons = [FakeLLUDPEncryptionAddon()]
