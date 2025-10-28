# DNS Monitor & Tester (Python)

Passive DNS monitoring and spoof-detection tools built in Python (two scripts included).  
- `dns_monitor.py` — passive DNS watcher that inspects live DNS traffic and raises alerts for suspicious responses (resolver mismatch, unsolicited replies, low TTLs, private IPs in answers, multiple A records, non-zero RCODEs).  
- `dns_tester.py` — small Scapy-based test harness to simulate DNS anomalies (resolver mismatch, TXID mismatch, unsolicited response, low TTL, private IP, conflicting A, NXDOMAIN) for lab validation.

> ⚠️ **Ethics:** Only run these tools on networks and machines you control or where you have explicit permission. `dns_monitor.py` requires elevated privileges to sniff interfaces; `dns_tester.py` sends crafted packets — use in a lab.

---

## Key features

- **Passive capture** (no active probes) using Scapy — inspects UDP/TCP port 53 traffic.  
- **Spoof detection heuristics**: unsolicited responses, resolver mismatch, non-zero RCODEs.  
- **Answer analysis**: flags low TTLs, private IPs in answers, and multiple/conflicting A records.  
- **In-memory transaction tracking**: short time-windowed query store to correlate queries → responses.  
- **JSON-line alerts**: optional append-to-file output for later analysis.  
- **Test harness** (`dns_tester.py`): simulate attacks/edge cases to validate detection logic.

---

## Requirements

- Python 3.9+  
- `scapy` (`pip install scapy`)  
- Root / sudo privileges to sniff or send raw packets (`sudo python3 ...`)  
- Linux or macOS recommended (some sniffing behavior differs on Windows)

---

## Quick flags & options

**dns_monitor.py**
- `--iface -i` — interface to sniff (default: scapy chooses)  
- `--window` — seconds to keep recent queries (default 15.0)  
- `--output -o` — append alerts to JSON-lines file (optional)  
- `--pcap` — (placeholder) save live capture to a pcap file (not implemented)  
- `--verbose -v` — verbose logging

**dns_tester.py**
- `--mode` — choose a scenario (`resolver_mismatch`, `unsolicited`, `txid_mismatch`, `low_ttl`, `private_ip`, `conflicting_a`, `nxdomain`)  
- `--qname` — domain to test (default `example.com`)  
- `--txid` — optional transaction id (hex OK)  
- `--client-port` — client source port used in tests (default 33333)  
- `--spoof-src` / `--spoof-ans` — forged responder IP and answer IP  
- `--seed` — RNG seed for reproducibility

---

## Notes on behavior & caveats

- `dns_monitor.py` is **passive** — it only listens and correlates observed queries/responses. It does not transmit packets.  
- The script keeps a short history of queries (configurable with `--window`) to match responses; increase window if responses are delayed.  
- Private IPs in answers or very low TTLs may indicate misconfiguration, captive portals, or malicious responses — investigate contextually.  
- `dns_tester.py` **injects** crafted DNS responses — use only on localhost, isolated VMs, or lab networks. Sending spoofed packets on public networks can be illegal.  
- Alert output is JSON-lines (one JSON object per line) when `--output` is used; this makes it easy to `jq`/parse programmatically.

---

## Example (lab-only)

```bash
# Run the passive monitor on wlan0 and append alerts to alerts.json
sudo python3 dns_monitor.py --iface wlan0 --window 20 --output alerts.json --verbose

# In another terminal (lab VM / localhost), simulate a resolver mismatch:
sudo python3 dns_tester.py --mode resolver_mismatch --qname example.com --spoof-src 198.51.100.5
