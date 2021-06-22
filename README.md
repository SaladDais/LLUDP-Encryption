A proposal for a transport encryption scheme for software compatible with Second Life's LLUDP protocol.

See the diff: https://github.com/SaladDais/LLUDP-Encryption/compare/lludp_encryption_base...lludp_encryption

# Why add transport encryption?

* UDP source address spoofing is a problem
* * LLUDP uses source address to see if message is from a trusted sender, so attackers can spoof a source address
    to pretend they're the sim
* * Not all networks employ [BCP38](https://tools.ietf.org/html/bcp38), UDP spoofing commonly abused for DNS / NTP
    amplification DoS, and this affects many other unauthenticated UDP protocols
* * Probable reason for UDP blacklisting for specific messages being added to LLUDP ages ago, but only covers a couple cases
* * Authenticated transport encryption would fully solve this problem by not relying solely on the sender's supposed address!
* More people use Second Life on untrusted Wi-Fi than when the protocol was created
* * Anyone listening on the WiFi can pull the unencrypted Session ID from a message and transfer out all
    the victim's money, as was demonstrated over a decade ago
* Doesn't limit server host's ability to monitor for abuse, since the server host must be able to decrypt all messages
* It's cool to encrypt

# Proposal
Doesn't use existing encrypted UDP networking standard like DTLS or QUIC

* DTLS and QUIC don't map cleanly to existing MessageSystem notions about reliability / ordering
  so this would be a major undertaking.
* * Similar issue with using a more game-oriented schemes like Steam's [GameNetworkingSockets](https://github.com/ValveSoftware/GameNetworkingSockets)
* MessageSystem quirks are not well understood anymore, so best to keep changes as un-intrusive and
  limited in scope as possible.
* SL's UDP connections are always bootstrapped via a trusted HTTPS connection (event queue / login req)
  so another layer of PKI is unnecessary.
* DTLS and QUIC support in languages used by third party clients is still lacking

Uses 256-bit AES-GCM, key constructed from `HMAC_SHA256(session_id, sim_address || sim_port)`.
AES-GCM is an AEAD cipher that ensures integrity and authenticity as well as confidentiality.

Designed to be as simple as possible to implement in the most popular SL protocol implementations.

This scheme is fully backwards-compatible, and clients can still connect to sims that don't support encryption.

## Packet format

```
UDP Header:
    // indicates message is encrypted, no other flags may be set.
    // for symmetry with unencrypted UDP packet header, allows both
    // encrypted and unencrypted messages to be sent over the same port.
    U8 send_flags = 0x08
    U8 version = 0x01
    U8 nonce[12] = <4 byte packet id + 8 bytes random>
    // will be used to look up the shared secret used to encrypt the packet
    U32 circuit_code
    // whatever's left is the ciphertext, contains encrypted message.
    // last 16 bytes are authentication tag
    U8 ciphertext[...]
```

The ciphertext contains a complete, encrypted version of an LLUDP message, including packet ID, headers, and acks field.
When decrypted, it should be indistinguishable from other messages of the existing, unencrypted message form.

indra's newsim already has a map of circuit code -> session ID, so no extra state needs to be passed around between
sims to support encryption. Sims only need to know which encryption versions their neighbours and teleport destination
regions support so that they can inform clients.

# Trying it out

This repo includes a Firestorm implementation with the LLUDP encryption patches applied. Since there are no
real implementations of the server-side portion of the encryption, an addon for the
[Hippolyzer proxy](https://github.com/SaladDais/Hippolyzer) is provided at
<https://github.com/SaladDais/LLUDP-Encryption/blob/lludp_encryption/proxy_addon/fake_lludp_encryption.py>.
It mimics an encryption-aware grid by wrapping unencrypted sim connections with encryption.

# Usual circuit setup flow

* Sim is informed by some other server that a client will connect with a given circuit code and session id.
  Sim stores the info in a local map of pending circuits.
* Client is informed via Event Queue or login response of the sim IP and port they should connect to
* * Due to NAT the servers can't be sure what IP and source port a client will connect from.
* Client sends a `UseCircuitCode` with their agent ID, circuit code and session ID they received in their
  initial login response.
* Sim looks up the circuit code in its map and checks that the provided circuit code and session ID exist
  in its map.
* If the provided circuit code and session ID exist in the map, the sim creates an entry in its list of
  valid circuits keyed on the address the `UseCircuitCode` was received from. The created circuit is strongly
  tied to the agent ID and session ID.

# Proposed encrypted circuit setup flow

* When sim starts up it tells grid services whether it supports encryption.
* Sim is informed by some other server that a client will connect with a given circuit code and session id.
  Sim stores the info in a local map of pending circuits.
* Client is informed via Event Queue or login response of the sim IP and port they should connect to,
  along with whether the sim supports encrypted connections.
* * Due to NAT the servers can't be sure what IP and source port a client will connect from.
* Client sends a `UseCircuitCode` with their agent ID, circuit code and session ID they received in their
  initial login response. If the client was informed that the sim supports encryption, the client may
  encrypt the `UseCircuitCode` message, tagging the encrypted message with its circuit code so the sim
  knows which key to use to decrypt the message.
* Sim checks if the message is encrypted, if it is:
* * Sim checks if it already has a valid circuit for the sending address. If so, it uses the associated key
* * If there was not existing circuit or no associated key, the sim checks if it has a session ID associated
    with the circuit code from encrypted message's header and uses that to derive a key.
* * If the sim was still unable to determine the key used to encrypt the message it refuses to process it.
    Otherwise it decrypts the message using the key. The decrypted message should have the exact same
    representation as a typical unencrypted message sent over the wire, so message processing continues as before.
* Sim looks up the circuit code from the underlying message (not the encrypted message's header, if there was one)
  in its map and checks that the provided circuit code and session ID exist in its map.
* If the provided circuit code and session ID exist in the map, the sim creates an entry in its list of
  valid circuits keyed on the address the `UseCircuitCode` was received from. The created circuit is strongly
  tied to the agent ID and session ID. If the `UseCircuitCode` was encrypted, all messages sent by the sim from
  that point on will be encrypted.

# Caveats

## No key negotiation at circuit setup like TLS does
Connecting to the same circuit address twice in the same session uses the same key. This allows replay attacks
via an active man-in-the-middle if the client re-connects to the same sim. Key negotiation would be preferable,
but adds many steps to connection setup. MessageSystem has many corner cases and few tests, annoying to get right.

Originally the design used the `HMAC_SHA256(session_id, sim_addr || sim_port)` key to encrypt only the
initial `UseCircuitCode` message, and had the client send along 32 random bytes. Then the server would send
back 32 of its own bytes in a new message, `AckCircuitEncryption`. After that packet had been acked, both
ends would switch to communicating using the key `HMAC_SHA256(base_circuit_key, client_random || server_random)`.

This was decided against because it would add an extra, half-open state to circuits before communication could happen
that would need to be accounted for. There's no technical reason it couldn't be added later, there's just a 0% chance
of anyone wanting to implement that vs 2% for this version :).

## AES-GCM is not resistant to nonce misuse

[AES-GCM-SIV](https://en.wikipedia.org/wiki/AES-GCM-SIV) would be preferred but nobody implements it. This isn't
generally an issue so long as implementers are careful to not repeat nonces. With the nonce generation scheme
implemented here it's extremely unlikely that a nonce will be repeated. The benefits of using an AEAD cipher like
AES-GCM that ties the integrity and authenticity checks to decryption outweigh the harm, providing no way
for implementors to not do those checks.

## Limited visibility for legitimate man-in-the-middle tools

Tools like `tcpdump` and Wireshark are less useful for debugging issues when connections are encrypted, which can
make live debugging issues harder. This is made a little easier by the key ID being included in every message,
so if you have a circuit code -> session ID map you can post-process your pcap files to decrypt them.

Tools that are aware of session state like Hippolyzer, or in-viewer tools like Alchemy's message log should not
have any issues debugging messages sent over encrypted circuits.

# License

This patchset is applied on top of Firestorm for demo purposes, Firestorm is licensed under the LGPL v2.1.

The diffs of any commits written by me in https://github.com/SaladDais/LLUDP-Encryption/compare/lludp_encryption_base...lludp_encryption
may be used under the terms of public domain, ISC, LGPL v2.1 or Apache v2 licenses. Whatever your lawyers prefer.
Note that the code will probably become LGPL v2.1 when applied unless you're the original copyright holder for the SL viewer.

All documents and designs in these diffs authored by me have the same licensing terms as above
and may be used without attribution.
