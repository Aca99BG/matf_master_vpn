# MATF Master VPN

Research prototype for designing and implementing a VPN and analyzing its
security and performance. The implementation targets Linux and uses Python,
a TUN interface, UDP transport, authenticated encryption, and a PyQt client.

This is an educational prototype, not a production VPN and not an audited
security product.

## Scope

The project includes:

- an IPv4 point-to-point tunnel over a Linux TUN interface;
- a Python client and server;
- authenticated encryption using established cryptographic libraries;
- session handling and replay protection;
- a PyQt client for connection management and status;
- reproducible latency, throughput, jitter, loss, and resource measurements;
- comparison with a direct connection, WireGuard, and OpenVPN.

The first version excludes TAP/Ethernet bridging, IPv6, mobile platforms,
peer-to-peer topology, and production deployment guarantees.

## Milestones

This list is frozen; implementation details will not create new top-level
milestones.

1. [x] Define and test the binary packet format.
2. [x] Exchange packets over an unencrypted UDP transport.
3. [x] Connect Linux network namespaces through TUN interfaces.
4. [x] Add AES-GCM, directional PSK derivation, nonce management, and replay protection.
5. [x] Add static X25519 peer key agreement.
6. [x] Add an authenticated ephemeral X25519 handshake with forward secrecy.
7. [x] Add packet-count-based key rotation.
8. [x] Add JSON configuration, structured logging, and initial reconnect.
9. [x] Add active-session liveness detection and reconnect.
10. [x] Add multiple-client server support.
11. [x] Build the PyQt client on top of the tested VPN engine.
12. [x] Automate local and Azure-ready performance experiments.
13. [ ] Analyze security, results, limitations, and comparison baselines.

## Development

Run the current unit tests without installing the package:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Run an endpoint from a validated JSON profile:

```bash
sudo PYTHONPATH=src python3 -m matf_vpn --config examples/client.example.json
```

Key paths in a profile are resolved relative to the profile file. The example
uses documentation-only addresses and must be copied into a deployment-specific
profile before use. `json_logs` emits one JSON object per line for ingestion by
benchmark and monitoring tools.

Launch the PyQt client with a preselected profile:

```bash
PYTHONPATH=src python3 -m matf_vpn.gui --profile examples/client.example.json
```

The GUI validates the profile, requests privileges through `pkexec` only when
Connect is pressed, shows connection/reconnect state, and streams structured
endpoint events. Disconnect terminates the managed endpoint process.

Run the privileged end-to-end test on Linux after loading the TUN module:

```bash
sudo modprobe tun
sudo bash scripts/test_namespace_tunnel.sh
```

Run the two-client server test:

```bash
sudo bash scripts/test_multi_client_tunnel.sh
```

Run the real PyQt Connect/Disconnect lifecycle test:

```bash
sudo bash scripts/test_gui_tunnel.sh
```

Performance methodology and commands are documented in
[docs/benchmarking.md](docs/benchmarking.md). The local orchestrator measures
direct, plaintext Python, and encrypted Python modes under identical namespace
conditions and writes raw JSON plus a comparison CSV.

The implemented threat model, controls, and residual risks are documented in
[docs/security-analysis.md](docs/security-analysis.md). The first automated
smoke dataset and the requirements for defensible final experiments are in
[docs/preliminary-results.md](docs/preliminary-results.md).

A complete real-world Azure server, GUI client, key exchange, private-tunnel,
full-tunnel NAT, and remote benchmark procedure is in
[docs/azure-deployment.md](docs/azure-deployment.md).

The script creates two temporary network namespaces, exchanges ICMP traffic
through the Python TUN/UDP data plane, and removes all test resources on exit.

Generate a persistent X25519 identity for each endpoint:

```bash
PYTHONPATH=src python3 -m matf_vpn.keygen \
	--private-key client.key \
	--public-key client.pub
```

Exchange only the `.pub` files. Each endpoint starts with its own private key,
the other endpoint's public key, and the appropriate `--role` value. Static
mode also requires a shared session ID; ephemeral mode negotiates a fresh one.
Private key files are created with mode `0600` and are never sent over the
network.

The static X25519 mode authenticates possession of configured peer keys but
does not provide forward secrecy. The optional authenticated ephemeral
handshake combines fresh ephemeral and configured static X25519 exchanges,
providing a fresh session secret and forward secrecy. Periodic in-session key
rotation remains a separate milestone.

Validated on 2026-08-20 with 3/3 ICMP packets received and 0% packet loss:

- plaintext baseline: 0.403 ms average RTT;
- AES-256-GCM with directional PSK-derived keys: 1.007 ms average RTT;
- AES-256-GCM with static X25519 agreement and directional keys: 1.386 ms
	average RTT;
- AES-256-GCM after an authenticated ephemeral X25519 handshake: 1.471 ms
	average RTT;
- ephemeral X25519 with forced rotation every two packets: 0.615 ms average
	RTT, with traffic successfully crossing from key epoch 0 to epoch 1;
- JSON profile startup with forced initial reconnect, structured event checks,
	ephemeral X25519, and rotation: 1.507 ms average RTT;
- active peer failure and re-handshake: 1.651 ms average RTT before the forced
	server failure and 1.114 ms after recovery, both with 0% packet loss.

These short smoke-test measurements prove functionality but are not benchmark
results. Performance conclusions require warm-up, randomized repeated runs,
larger samples, confidence intervals, and controlled CPU/network conditions.
The ICMP measurements start after session establishment and therefore measure
data-plane RTT, not handshake latency. Handshake duration must be measured as
a separate metric.

Packet-count rotation limits the amount of data protected by one AES key and
supports out-of-order delivery by selecting the epoch from the packet sequence
number. Epoch keys are derived from the session master secret, so this mechanism
does not provide post-compromise security within an already established
session. A fresh authenticated ephemeral handshake is required for a new
independent master secret.

The operational smoke test delays the server so the client exhausts its first
handshake cycle, then later terminates an established server process. It
verifies structured reconnect and session events, starts a new authenticated
ephemeral session, and confirms traffic before and after active peer failure.

The multi-client smoke test validates two independently authenticated clients
on one server UDP socket and TUN interface. Each client has isolated cipher,
sequence, and replay state, a unique tunnel address, destination-based routing,
and source-address anti-spoofing enforcement.

The benchmark smoke run successfully produced raw JSON for direct, plaintext
Python, and encrypted Python modes plus a comparison CSV. With one repetition,
it observed 32.86 Gbps direct TCP, 223.34 Mbps plaintext tunnel TCP, and 75.98
Mbps encrypted tunnel TCP. UDP was capped at 100 Mbps; the encrypted run
observed 0.55% loss. These values validate collection and reporting only and
must not be used as final thesis results.

## Azure role

Azure is reserved for the externally reachable VPN server and repeatable
comparison experiments. Local network namespaces remain the primary
development environment. Cloud resources must be deallocated outside test
windows, use a budget alert, and keep all compared VPNs on identical VM sizes
and network paths.
