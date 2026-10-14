#!/usr/bin/env python3
"""
Post-quantum TLS survey.

For every server in servers.txt:
  1. Start a tshark capture on Wi-Fi filtered to that server's IP (port 443).
  2. Handshake #1 ("PQ offered"): OpenSSL 3.5 defaults, which offer the hybrid
     X25519MLKEM768 key share first, plus classical X25519 as a fallback.
     Whatever the server picks shows if it supports post-quantum key exchange.
  3. Handshake #2 ("classical only"): offer only classical groups, for a size
     comparison on the same server.
  4. Stop the capture and extract the handshake fields with tshark.

Writes captures/servers/<host>.pcapng, results/results.csv and results/results.md.
Only uses the Python standard library.
"""
import csv
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CAP_DIR = ROOT / "captures" / "servers"
OUT_DIR = ROOT / "results"
INTERFACE = "en0"  # Wi-Fi on a MacBook

OPENSSL = Path(subprocess.run(["brew", "--prefix", "openssl@3"], capture_output=True,
                              text=True).stdout.strip()) / "bin" / "openssl"
TSHARK = shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"

CLASSICAL_GROUPS = "X25519:P-256:P-384"

# TLS named-group codepoints (IANA) -> readable names
GROUP_NAMES = {
    "4588": "X25519MLKEM768", "29": "x25519", "23": "secp256r1",
    "24": "secp384r1", "25": "secp521r1", "30": "x448",
}
PQ_GROUPS = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}


def openssl_handshake(host, ip, groups=None):
    """Run one TLS handshake and return the key exchange OpenSSL reports."""
    cmd = [str(OPENSSL), "s_client", "-connect", f"{ip}:443", "-servername", host]
    if groups:
        cmd += ["-groups", groups]
    out = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=20).stdout
    protocol, group = "", ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Negotiated TLS1.3 group:"):
            group = line.split(":", 1)[1].strip()
        elif line.startswith("Peer Temp Key:") and not group:
            group = line.split(":", 1)[1].split(",")[0].strip()
            if group == "ECDH":  # e.g. "ECDH, secp384r1, 384 bits"
                group = line.split(",")[1].strip()
        elif line.startswith("Protocol:") or line.startswith("Protocol  :"):
            protocol = line.split(":", 1)[1].strip()
    return protocol, group


def tshark_fields(pcap):
    """Pull ClientHello / ServerHello fields out of a capture with tshark."""
    fields = ["tcp.stream", "tls.handshake.type",
              "tls.handshake.extensions_key_share_group",
              "tls.handshake.extensions_key_share_key_exchange_length",
              "tls.handshake.server_point_len",
              "tls.handshake.length",
              "tcp.segment.count", "tcp.reassembled.length", "frame.len"]
    cmd = [TSHARK, "-r", str(pcap), "-Y", "tls.handshake.type == 1 || tls.handshake.type == 2 || tls.handshake.type == 12",
           "-T", "fields", "-E", "separator=|", "-E", "aggregator=;"]
    for f in fields:
        cmd += ["-e", f]
    rows = []
    for line in subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines():
        rows.append(dict(zip(fields, line.split("|"))))
    return rows


def summarize_stream(rows, stream):
    """Client/server key share info for one TCP connection (one handshake)."""
    info = {"client_groups": "", "client_share_bytes": "", "server_share_bytes": "",
            "clienthello_bytes": "", "clienthello_segments": "1"}
    for r in rows:
        if r["tcp.stream"] != stream:
            continue
        types = r["tls.handshake.type"].split(";")
        if "1" in types:  # ClientHello
            groups = [GROUP_NAMES.get(g, g) for g in r["tls.handshake.extensions_key_share_group"].split(";") if g]
            lens = [l for l in r["tls.handshake.extensions_key_share_key_exchange_length"].split(";") if l]
            info["client_groups"] = " + ".join(groups)
            info["client_share_bytes"] = " + ".join(lens)
            info["clienthello_bytes"] = r["tls.handshake.length"].split(";")[0]
            if r["tcp.segment.count"]:
                info["clienthello_segments"] = r["tcp.segment.count"].split(";")[0]
        if "2" in types and r["tls.handshake.extensions_key_share_key_exchange_length"]:
            info["server_share_bytes"] = r["tls.handshake.extensions_key_share_key_exchange_length"].split(";")[0]
        if "12" in types and r["tls.handshake.server_point_len"]:  # TLS 1.2 ServerKeyExchange
            info["server_share_bytes"] = r["tls.handshake.server_point_len"].split(";")[0]
    return info


def risk(protocol, group):
    if group in PQ_GROUPS:
        return "Low: hybrid post-quantum key exchange"
    if not group:
        return "Unknown"
    return f"HIGH: classical only ({'ECDHE ' + group}) -> harvest now, decrypt later"


def survey(host):
    ip = socket.gethostbyname(host)  # IPv4, so the capture filter matches
    pcap = CAP_DIR / f"{host}.pcapng"
    cap = subprocess.Popen([TSHARK, "-i", INTERFACE, "-f", f"tcp port 443 and host {ip}",
                            "-w", str(pcap), "-q"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)  # let tshark start
    try:
        pq_proto, pq_group = openssl_handshake(host, ip)
        time.sleep(0.5)
        cl_proto, cl_group = openssl_handshake(host, ip, CLASSICAL_GROUPS)
        time.sleep(1.5)  # let the last packets arrive
    finally:
        cap.terminate()
        cap.wait()

    rows = tshark_fields(pcap)
    pq = summarize_stream(rows, "0")
    cl = summarize_stream(rows, "1")
    return {
        "host": host, "ip": ip, "tls_version": pq_proto,
        "negotiated_group": pq_group,
        "pq_supported": "yes" if pq_group in PQ_GROUPS else "no",
        "client_key_shares": pq["client_groups"],
        "client_share_bytes": pq["client_share_bytes"],
        "server_share_bytes": pq["server_share_bytes"],
        "clienthello_bytes": pq["clienthello_bytes"],
        "clienthello_tcp_segments": pq["clienthello_segments"],
        "classical_group": cl_group,
        "classical_client_share_bytes": cl["client_share_bytes"],
        "classical_server_share_bytes": cl["server_share_bytes"],
        "classical_clienthello_bytes": cl["clienthello_bytes"],
        "hndl_risk": risk(pq_proto, pq_group),
    }


def write_markdown(results, path):
    lines = ["| Server | TLS | Negotiated group | PQ? | Server key share (bytes) | Harvest-now-decrypt-later risk |",
             "|---|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['host']} | {r['tls_version']} | {r['negotiated_group']} | {r['pq_supported']} "
                     f"| {r['server_share_bytes']} | {r['hndl_risk']} |")
    pq = sum(r["pq_supported"] == "yes" for r in results)
    lines += ["", f"**{pq} of {len(results)} servers negotiated post-quantum key exchange; "
                  f"{len(results) - pq} are classical only.**"]
    path.write_text("\n".join(lines) + "\n")


def main():
    CAP_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(exist_ok=True)
    hosts = [h.strip() for h in (ROOT / "servers.txt").read_text().splitlines()
             if h.strip() and not h.startswith("#")]
    results = []
    for host in hosts:
        print(f"[*] {host} ...", end=" ", flush=True)
        try:
            r = survey(host)
        except Exception as e:  # keep going if one server fails
            print(f"failed: {e}")
            continue
        results.append(r)
        print(f"{r['negotiated_group']} ({r['tls_version']}), ClientHello {r['clienthello_bytes']} bytes "
              f"in {r['clienthello_tcp_segments']} TCP segment(s)")

    with open(OUT_DIR / "results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)
    write_markdown(results, OUT_DIR / "results.md")
    print(f"\nSaved results/results.csv and results/results.md")


if __name__ == "__main__":
    sys.exit(main())
