# Security analysis

## Scope and assets

The protected assets are IPv4 packet confidentiality, integrity, peer
authenticity, session keys, long-term identity keys, tunnel address ownership,
and endpoint availability. The attacker is assumed to control the network and
may observe, inject, modify, duplicate, reorder, delay, or drop UDP datagrams.

Endpoint compromise, malicious local administrators, kernel compromise,
traffic-analysis resistance, anonymity, and post-quantum security are outside
the prototype's guarantees.

## Implemented controls

| Threat | Control | Validation |
|---|---|---|
| Passive packet inspection | AES-256-GCM encrypts IPv4 payloads | Ciphertext differs from plaintext and decrypts only with the directional peer key |
| Packet modification | VPN header is AES-GCM associated data; payload includes the authentication tag | Header and ciphertext modification tests raise `InvalidTag` |
| Peer impersonation | Static X25519 identity keys authenticate both ephemeral handshake messages with HMAC-SHA256 | Unknown client keys and modified handshake messages are rejected |
| Long-term key compromise after a session | Fresh ephemeral X25519 exchanges contribute to every negotiated master secret | Repeated handshakes derive different secrets; captured sessions do not depend only on static keys |
| Nonce reuse between directions | HKDF derives independent client-to-server and server-to-client keys | A packet cannot be decrypted with the cipher for the wrong direction |
| Nonce reuse within a direction | Nonce is the 32-bit session ID concatenated with the 64-bit sequence number | Sequence numbers are monotonic and exhaustion stops transmission |
| Packet replay | Per-session 64-packet sliding replay window | Duplicate and packets outside the window are rejected; out-of-order packets inside it are accepted once |
| Client tunnel-address spoofing | Multi-client server binds each authenticated identity to one IPv4 source address | Authenticated payload with another client's source address is rejected |
| Stale key exposure volume | Packet-count epochs derive new AES keys from the session master secret | Traffic crosses tested epoch boundaries and supports previous-epoch reordering |
| Silent peer failure | Authenticated encrypted keepalives and monotonic liveness deadlines | Established server termination triggers a fresh authenticated session and recovered traffic |
| Malformed network input | Invalid wire packets and unsupported non-IPv4 payloads are dropped | Regression tests prove malformed datagrams no longer terminate endpoint loops |
| Captured handshake replay | Bounded idempotent server cache returns the original response without replacing active route/cipher state | Replayed `CLIENT_HELLO` is marked non-new and preserves the existing session object |

Private key files must have no group or other-user permissions. The key
generator creates private files atomically with mode `0600` and refuses to
overwrite an existing identity. Keys are not accepted as command-line values
and are not written to structured logs.

## Protocol properties

Each authenticated ephemeral handshake combines four X25519 results:

- ephemeral-to-ephemeral;
- client-ephemeral-to-server-static;
- client-static-to-server-ephemeral;
- static-to-static.

The handshake transcript is authenticated and used as the HKDF salt. Session
traffic uses independent directional keys. Header fields including message
type, session ID, sequence number, and encrypted payload length are
authenticated as associated data.

Forward secrecy is a protocol-design property here, not a hardened memory
erasure claim. Python and the cryptographic backend may leave obsolete key
material in process memory until overwritten or reclaimed.

## Residual risks and limitations

- The code is a research prototype and has not received an independent audit.
- The VPN process runs with elevated privileges. A production design should
  isolate interface setup, drop privileges, and retain only required
  capabilities.
- Handshake authentication work is performed before rate limiting. A remote
  attacker can consume CPU with invalid hello messages, particularly when the
  client registry is large.
- The handshake replay cache is bounded. Very old entries can be evicted and
  replayed as an availability attack, although confidentiality is not gained.
- A 32-bit random session identifier has a non-zero collision probability.
  Collision handling should be strengthened for long-running, high-session
  deployments.
- Packet-count rotation derives epoch keys from one master secret. It limits
  data per AES key but does not provide post-compromise security within the
  active session. A new ephemeral handshake is required.
- The 64-packet replay window can reject legitimate packets under extreme UDP
  reordering.
- No congestion control, path-MTU discovery, fragmentation strategy, or IPv6
  data plane is implemented.
- UDP source addresses, packet sizes, timing, and traffic volume remain visible
  to network observers.
- Multi-client sessions are replaced on re-authentication but currently have no
  independent server-side idle expiry policy.
- Availability cannot be guaranteed against packet dropping, volumetric DoS,
  endpoint failure, or compromise of the underlying host.

## Security conclusion

The prototype demonstrates confidentiality, integrity, mutual configured-peer
authentication, replay resistance, directional key separation, forward-secret
session establishment, and client address isolation. These controls support
the thesis experiments, but they do not make the implementation suitable for
production use without protocol review, fuzzing, privilege separation,
rate-limiting, dependency updates, and an independent security audit.
