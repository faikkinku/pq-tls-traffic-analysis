# Post-Quantum TLS Traffic Analysis

Capturing and comparing TLS 1.3 handshakes that use classical **X25519** key exchange versus hybrid post-quantum **X25519MLKEM768** (ML-KEM-768, NIST FIPS 203), using Wireshark, tshark, OpenSSL 3.5 and Python.

*Work in progress. Full results and display filters coming.*

## First capture: Cloudflare, PQ vs classical

`captures/01_cloudflare_pq_vs_classical.pcapng` (filtered to `tcp port 443 and host 104.16.132.229`)

| Handshake | Group | Client key share | Server key share | ClientHello |
|---|---|---|---|---|
| Post-quantum | X25519MLKEM768 (0x11ec) | 1,216 bytes | 1,120 bytes | 1,416 bytes, reassembled from 2 TCP segments |
| Classical | x25519 (0x001d) | 32 bytes | 32 bytes | fits in 1 segment |

The client key share is 1,184-byte ML-KEM-768 encapsulation key + 32-byte X25519 key = 1,216 bytes (38x larger).
The server replies with a 1,088-byte ML-KEM ciphertext + 32-byte X25519 key = 1,120 bytes.
