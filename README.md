# Post-Quantum TLS Traffic Analysis

Capturing and dissecting TLS 1.3 handshakes in Wireshark to compare classical **X25519** key exchange against the hybrid post-quantum **X25519MLKEM768** (ML-KEM-768, NIST FIPS 203), then surveying 10 public servers to see which ones still use quantum-vulnerable key exchange.

**Tools:** Wireshark 4.6, tshark, OpenSSL 3.5.9, Python 3 (standard library only), macOS on Wi-Fi (`en0`).

Built as a hands-on follow-up to what I studied in CSCE 3530 (Computer Networks) and CSCE 3550 (Foundations of Cybersecurity) at UNT.

## Why this matters

In a TLS 1.3 handshake, the client and server each send a **key share** and combine them into a shared secret. With classical ECDHE (X25519, P-256, P-384), a large enough quantum computer could later recover that secret from a recording of the handshake. An attacker can **harvest now, decrypt later**: record encrypted traffic today and decrypt it once quantum computers exist.

The hybrid group **X25519MLKEM768** (TLS codepoint `0x11ec` / 4588) combines X25519 with ML-KEM-768. The connection stays secure unless *both* are broken. The cost is size:

| | Classical X25519 | Hybrid X25519MLKEM768 |
|---|---|---|
| Client key share | 32 bytes | **1,216 bytes** = 1,184-byte ML-KEM encapsulation key + 32-byte X25519 (**38x**) |
| Server key share | 32 bytes | **1,120 bytes** = 1,088-byte ML-KEM ciphertext + 32-byte X25519 |

## Finding 1: The key share grows 38x (Cloudflare)

`captures/01_cloudflare_pq_vs_classical.pcapng`, two `openssl s_client` handshakes to the same Cloudflare IP, one with `-groups X25519MLKEM768` and one with `-groups X25519`.

| Handshake | Group | Client key share | Server key share | ClientHello |
|---|---|---|---|---|
| Post-quantum | X25519MLKEM768 | 1,216 bytes | 1,120 bytes | reassembled from **2 TCP segments** |
| Classical | x25519 | 32 bytes | 32 bytes | 1 segment |

## Finding 2: Chrome's ClientHello no longer fits in one packet (Wikipedia)

`captures/02_chrome_clienthello_wikipedia.pcapng`, a fresh Chrome Incognito visit to wikipedia.org over TCP (Wikipedia doesn't advertise HTTP/3, so the browser doesn't use QUIC/UDP).

- Chrome offers **three** key shares: GREASE (1 byte), **X25519MLKEM768 (1,216 bytes)** and x25519 (32 bytes) as a fallback.
- The ClientHello is **1,989 bytes**. The TCP handshake agreed on an MSS of 1,440 bytes (client 1,460 from the 1,500-byte Ethernet/Wi-Fi MTU, server 1,440), minus 12 bytes of TCP timestamp option = **1,428 bytes of payload per segment**.
- So the ClientHello is split across **2 TCP segments** (1,428 + 561 bytes) and Wireshark shows it as `[2 Reassembled TCP Segments (1989 bytes)]`.
- Wikipedia's ServerHello picks **X25519MLKEM768** with a 1,120-byte key share.
- The record layer still says `TLS 1.2 (0x0303)`. That's TLS 1.3's *middlebox compatibility mode*; the real version is in the `supported_versions` extension.

## Finding 3: 5 of 10 servers are still quantum-vulnerable

[`analyze.py`](analyze.py) automates the survey with Python and tshark. For each host in [`servers.txt`](servers.txt) it:

1. starts a `tshark` capture on `en0` filtered to `tcp port 443 and host <server IP>`;
2. runs a handshake with OpenSSL 3.5 defaults, which offer X25519MLKEM768 **and** X25519, so the server chooses;
3. runs a classical-only handshake (`-groups X25519:P-256:P-384`) for comparison;
4. extracts the key share groups/lengths, ClientHello size and TCP segment count with `tshark -T fields`;
5. writes [`results/results.csv`](results/results.csv) and [`results/results.md`](results/results.md).

Results (Oct 13, 2026):

| Server | TLS | Negotiated group | Post-quantum? | Server key share | Harvest-now-decrypt-later risk |
|---|---|---|---|---|---|
| cloudflare.com | 1.3 | X25519MLKEM768 | yes | 1,120 B | Low |
| google.com | 1.3 | X25519MLKEM768 | yes | 1,120 B | Low |
| facebook.com | 1.3 | X25519MLKEM768 | yes | 1,120 B | Low |
| microsoft.com | 1.3 | X25519MLKEM768 | yes | 1,120 B | Low |
| wikipedia.org | 1.3 | X25519MLKEM768 | yes | 1,120 B | Low |
| github.com | 1.3 | X25519 | **no** | 32 B | **High**: classical ECDHE only |
| amazon.com | 1.3 | X25519 | **no** | 32 B | **High**: classical ECDHE only |
| unt.edu | 1.3 | X25519 | **no** | 32 B | **High**: classical ECDHE only |
| cisco.com | **1.2** | X25519 | **no** | 32 B | **High**: classical ECDHE only, TLS 1.2 |
| irs.gov | **1.2** | secp384r1 | **no** | 97 B | **High**: classical ECDHE (P-384) only, TLS 1.2 |

Every ClientHello in the survey was about 1,535 bytes and split across 2 TCP segments, because the client always offered the hybrid key share. Whether the connection ends up post-quantum is decided by the **server**. The classical servers still completed the handshake, using the X25519 fallback share.

## 5 reusable Wireshark display filters

| # | Filter | What it shows |
|---|---|---|
| 1 | `tls.handshake.type == 1` | Every **ClientHello**: what the client offers (versions, cipher suites, groups, key shares). |
| 2 | `tls.handshake.type == 2` | Every **ServerHello**: what the server actually picked. |
| 3 | `tls.handshake.extensions_key_share_group == 0x11ec` | Handshakes carrying an **X25519MLKEM768** key share. Add `&& tls.handshake.type == 2` to see only servers that *chose* post-quantum. |
| 4 | `tls.handshake.type == 1 && tcp.segment.count > 1` | ClientHellos that were **too big for one TCP segment** and had to be reassembled. |
| 5 | `tls.handshake.type == 2 && !(tls.handshake.extensions_key_share_group == 0x11ec)` | ServerHellos that did **not** pick the hybrid group: **classical key exchange to flag** (includes TLS 1.2 servers, which have no key_share extension). |

Bonus: `tls.handshake.extensions_supported_group == 0x11ec` finds clients that *advertise* post-quantum support.

## Reproduce

```bash
brew install openssl@3          # needs 3.5+ for ML-KEM
python3 analyze.py              # captures on en0; Wireshark's ChmodBPF must be installed
cat results/results.md
```

Single handshake by hand:

```bash
echo | $(brew --prefix openssl@3)/bin/openssl s_client -connect cloudflare.com:443 -tls1_3 -groups X25519MLKEM768 2>/dev/null | grep "group"
```

## Repository layout

```
analyze.py                 survey script (Python + tshark)
servers.txt                hosts to test
results/                   results.csv and results.md from the survey
captures/01_*.pcapng       Cloudflare PQ vs classical (OpenSSL)
captures/02_*.pcapng       Chrome ClientHello split across 2 TCP segments
captures/servers/*.pcapng  one capture per surveyed server
```

All captures use a capture filter on the single server IP, so they contain only that TLS traffic.
