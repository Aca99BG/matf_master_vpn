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

1. Define and test the binary packet format.
2. Exchange packets over an unencrypted UDP transport.
3. Connect Linux network namespaces through TUN interfaces.
4. Add AES-GCM, key establishment, nonce management, and replay protection.
5. Add configuration, reconnect behavior, logging, and multiple clients.
6. Build the PyQt client on top of the tested VPN engine.
7. Automate local and Azure performance experiments.
8. Analyze security, results, limitations, and comparison baselines.

## Development

Run the current unit tests without installing the package:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Azure role

Azure is reserved for the externally reachable VPN server and repeatable
comparison experiments. Local network namespaces remain the primary
development environment. Cloud resources must be deallocated outside test
windows, use a budget alert, and keep all compared VPNs on identical VM sizes
and network paths.
