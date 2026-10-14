| Server | TLS | Negotiated group | PQ? | Server key share (bytes) | Harvest-now-decrypt-later risk |
|---|---|---|---|---|---|
| cloudflare.com | TLSv1.3 | X25519MLKEM768 | yes | 1120 | Low: hybrid post-quantum key exchange |
| google.com | TLSv1.3 | X25519MLKEM768 | yes | 1120 | Low: hybrid post-quantum key exchange |
| facebook.com | TLSv1.3 | X25519MLKEM768 | yes | 1120 | Low: hybrid post-quantum key exchange |
| microsoft.com | TLSv1.3 | X25519MLKEM768 | yes | 1120 | Low: hybrid post-quantum key exchange |
| wikipedia.org | TLSv1.3 | X25519MLKEM768 | yes | 1120 | Low: hybrid post-quantum key exchange |
| github.com | TLSv1.3 | X25519 | no | 32 | HIGH: classical only (ECDHE X25519) -> harvest now, decrypt later |
| amazon.com | TLSv1.3 | X25519 | no | 32 | HIGH: classical only (ECDHE X25519) -> harvest now, decrypt later |
| unt.edu | TLSv1.3 | X25519 | no | 32 | HIGH: classical only (ECDHE X25519) -> harvest now, decrypt later |
| cisco.com | TLSv1.2 | X25519 | no | 32 | HIGH: classical only (ECDHE X25519) -> harvest now, decrypt later |
| irs.gov | TLSv1.2 | secp384r1 | no | 97 | HIGH: classical only (ECDHE secp384r1) -> harvest now, decrypt later |

**5 of 10 servers negotiated post-quantum key exchange; 5 are classical only.**
