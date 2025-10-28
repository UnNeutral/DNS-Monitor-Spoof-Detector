#!/usr/bin/env python3
"""
dns_monitor.py — Passive DNS watcher with simple spoof-detection heuristics.

Usage examples:
  sudo python3 dns_monitor.py --iface lo --output alerts.json
  sudo python3 dns_monitor.py -i wlan0 --window 20 --verbose
"""

from __future__ import annotations
import argparse
import json
import time
import logging
import ipaddress
from collections import deque, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Tuple

# scapy import (requires scapy installed)
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP

# -------------------------
# Configuration defaults
# -------------------------
KEEP_SECONDS = 15.0         # how long to remember queries
MIN_SUSPICIOUS_TTL = 30    # TTL under this is suspicious
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]


# -------------------------
# Simple records
# -------------------------
@dataclass
class QueryEntry:
    id: int
    name: str
    client_ip: str
    resolver_ip: str
    client_port: int
    resolver_port: int
    seen_at: float


@dataclass
class WarningRecord:
    time: str
    kind: str
    message: str
    details: Dict

    def to_dict(self) -> Dict:
        return asdict(self)


# In-memory store: key = (txid, qname) -> deque of QueryEntry
RECENT: Dict[Tuple[int, str], Deque[QueryEntry]] = defaultdict(lambda: deque(maxlen=8))


# -------------------------
# small helpers
# -------------------------
def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_epoch() -> float:
    return time.time()


def normalize_name(raw: bytes | str | None) -> str:
    if not raw:
        return ""
    try:
        if isinstance(raw, bytes):
            s = raw.decode(errors="ignore")
        else:
            s = str(raw)
        return s.lower().rstrip(".")
    except Exception:
        return str(raw).lower().rstrip(".")


def ip_is_private(ip_str: str) -> bool:
    try:
        a = ipaddress.ip_address(ip_str)
        return any(a in net for net in PRIVATE_NETS)
    except Exception:
        return False


def record_to_dict(q: QueryEntry) -> Dict:
    return {
        "id": q.id,
        "name": q.name,
        "client_ip": q.client_ip,
        "resolver_ip": q.resolver_ip,
        "client_port": q.client_port,
        "resolver_port": q.resolver_port,
        "seen_at": q.seen_at,
    }


# -------------------------
# core logic: store & match
# -------------------------
def remember_query(q: QueryEntry) -> None:
    key = (q.id, q.name)
    RECENT[key].append(q)
    # purge old items globally (cheap)
    cutoff = now_epoch() - KEEP_SECONDS
    for k, dq in list(RECENT.items()):
        while dq and dq[0].seen_at < cutoff:
            dq.popleft()
        if not dq:
            del RECENT[k]


def lookup_query(txid: int, qname: str) -> Optional[QueryEntry]:
    key = (txid, qname)
    dq = RECENT.get(key)
    if not dq:
        return None
    return dq[-1]  # recent


# -------------------------
# alert helper
# -------------------------
def raise_alert(out_list: List[WarningRecord], kind: str, msg: str, evidence: Dict) -> None:
    w = WarningRecord(time=iso_utc_now(), kind=kind, message=msg, details=evidence)
    out_list.append(w)
    logging.warning("%s %s - %s", w.time, kind, msg)


# -------------------------
# packet analyzer
# -------------------------
def analyze_packet(pkt, alarms: List[WarningRecord], args) -> None:
    # we only care about packets with a DNS layer
    if not pkt.haslayer(DNS):
        return

    dns = pkt[DNS]
    ip_layer = pkt[IP] if pkt.haslayer(IP) else None
    src_ip = ip_layer.src if ip_layer is not None else "0.0.0.0"
    dst_ip = ip_layer.dst if ip_layer is not None else "0.0.0.0"

    txid = int(dns.id)
    qname = ""
    if dns.qd and isinstance(dns.qd, DNSQR):
        qname = normalize_name(bytes(dns.qd.qname))

    # Query (QR=0)
    if dns.qr == 0:
        client_port = getattr(pkt, "sport", 0)
        resolver_port = getattr(pkt, "dport", 53)
        ent = QueryEntry(
            id=txid,
            name=qname,
            client_ip=src_ip,
            resolver_ip=dst_ip,
            client_port=client_port,
            resolver_port=resolver_port,
            seen_at=now_epoch(),
        )
        remember_query(ent)
        logging.debug("Query remembered: %s", record_to_dict(ent))
        return

    # Response (QR=1)
    evidence = {
        "txid": txid,
        "qname": qname,
        "resp_from": src_ip,
        "resp_to": dst_ip,
        "rcode": int(dns.rcode),
        "answers": int(dns.ancount),
    }

    matched = lookup_query(txid, qname)
    if matched is None:
        # no query seen recently
        raise_alert(alarms, "UNSOLICITED", f"No prior query for id={txid} name={qname}", {"response": evidence})
    else:
        # if response comes from a different IP than the resolver we saw the query go to
        if matched.resolver_ip != src_ip:
            raise_alert(
                alarms,
                "RESOLVER_MISMATCH",
                f"Query for {qname} went to {matched.resolver_ip} but reply came from {src_ip}",
                {"query": record_to_dict(matched), "response": evidence},
            )

    # RCODE check
    if dns.rcode != 0:
        raise_alert(
            alarms, "RCODE_NONZERO", f"Non-zero RCODE {dns.rcode} for {qname}", {"response": evidence}
        )

    # Analyze answers
    ttls: List[int] = []
    a_ips: List[str] = []
    private_found: List[str] = []

    for i in range(int(dns.ancount)):
        try:
            rr = dns.an[i]
        except Exception:
            continue
        # try read rdata and ttl
        rdata = None
        try:
            rdata = getattr(rr, "rdata", None)
        except Exception:
            rdata = None

        if rdata:
            ip_text = str(rdata)
            # crude test for IPv4 textual ip
            if ":" not in ip_text and any(ch.isdigit() for ch in ip_text):
                a_ips.append(ip_text)
                if ip_is_private(ip_text):
                    private_found.append(ip_text)

        # TTL
        try:
            if hasattr(rr, "ttl"):
                val = int(rr.ttl)
                ttls.append(val)
        except Exception:
            pass

    if ttls and min(ttls) < MIN_SUSPICIOUS_TTL:
        raise_alert(
            alarms,
            "LOW_TTL",
            f"Low TTL for {qname} (min={min(ttls)})",
            {"qname": qname, "ttls": ttls, "response": evidence},
        )

    if private_found:
        raise_alert(
            alarms,
            "PRIVATE_IP_IN_ANSWER",
            f"Private IPs in answer for {qname}: {private_found}",
            {"qname": qname, "private_ips": private_found, "response": evidence},
        )

    if len(set(a_ips)) > 1:
        raise_alert(
            alarms,
            "MULTIPLE_A",
            f"Multiple A records for {qname}: {a_ips}",
            {"qname": qname, "a_records": a_ips, "response": evidence},
        )


# -------------------------
# CLI and runner
# -------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Passive DNS watcher (lab use).")
    p.add_argument("--iface", "-i", help="Interface to sniff (scapy default if omitted)", default=None)
    p.add_argument("--window", type=float, help="Seconds to keep queries", default=KEEP_SECONDS)
    p.add_argument("--output", "-o", help="Write alerts to this file (append, json-lines)", default=None)
    p.add_argument("--pcap", help="Save live capture to pcap (not implemented)", default=None)
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    return p


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    # apply window if given
    global KEEP_SECONDS
    KEEP_SECONDS = float(args.window)

    logging.info("dns_watch starting (window=%.1fs)", KEEP_SECONDS)
    filters = "udp port 53 or tcp port 53"
    all_alerts: List[WarningRecord] = []

    sniff_options = dict(filter=filters, prn=lambda pkt: analyze_packet(pkt, all_alerts, args), store=False)
    if args.iface:
        sniff_options["iface"] = args.iface

    try:
        sniff(**sniff_options)
    except KeyboardInterrupt:
        logging.info("Interrupted by user, finishing up.")
    except PermissionError:
        logging.error("Permission error: run with sudo/root to sniff interfaces.")
        return 2
    except Exception as e:
        logging.exception("Sniffer error: %s", e)

    # dump alerts
    if args.output and all_alerts:
        try:
            with open(args.output, "a", encoding="utf-8") as fh:
                for w in all_alerts:
                    fh.write(json.dumps(w.to_dict()) + "\n")
            logging.info("Wrote %d alerts to %s", len(all_alerts), args.output)
        except Exception:
            logging.exception("Failed to write alerts to %s", args.output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

