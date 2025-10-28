#!/usr/bin/env python3
from __future__ import annotations

"""
dns_tester.py

Several small DNS test scenarios (lab only). Use --mode to pick the test.

Requires: pip install scapy
"""

"""
Usage examples to test out:-
sudo python3 dns_tester.py --mode resolver_mismatch
sudo python3 dns_tester.py --mode unsolicited
sudo python3 dns_tester.py --mode txid_mismatch --txid 0x1a2b
sudo python3 dns_tester.py --mode low_ttl
sudo python3 dns_tester.py --mode private_ip --spoof-src 198.51.100.5
sudo python3 dns_tester.py --mode conflicting_a
sudo python3 dns_tester.py --mode nxdomain
"""

import argparse
import os
import random
import sys
import time
from typing import Optional

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send

# ---- defaults ----
LOCAL = "127.0.0.1"
CLIENT_PORT = 33333
DEFAULT_QNAME = "example.com"
DEFAULT_FAKE_RESP_IP = "198.51.100.5"  # TEST-NET-2
DEFAULT_FAKE_ANS = "203.0.113.9"      # TEST-NET-3

# ---- helpers ----
def need_root():
    if os.geteuid() != 0:
        print("Run as root (sudo). Exiting.")
        sys.exit(1)


def pick_txid(provided: Optional[int]) -> int:
    return provided if provided is not None else random.randint(0, 0xFFFF)


def send_pkt(p):
    try:
        send(p, verbose=False)
    except Exception as e:
        print(f"[!] send failed: {e}")


def make_query(txid: int, qname: str, src=LOCAL, dst=LOCAL, sport=CLIENT_PORT):
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(id=txid, qr=0, rd=1, qd=DNSQR(qname=qname))


def make_response(txid: int, qname: str, resp_src: str, resp_dst: str, resp_dport: int, an_rr: Optional[DNSRR], rcode: int = 0, aa: int = 1):
    # Build a response; an_rr can be None for NXDOMAIN/no answer
    if an_rr is not None:
        return IP(src=resp_src, dst=resp_dst) / UDP(sport=53, dport=resp_dport) / DNS(
            id=txid, qr=1, aa=aa, rcode=rcode, qd=DNSQR(qname=qname), an=an_rr
        )
    # no answer (e.g., NXDOMAIN)
    return IP(src=resp_src, dst=resp_dst) / UDP(sport=53, dport=resp_dport) / DNS(
        id=txid, qr=1, aa=aa, rcode=rcode, qd=DNSQR(qname=qname)
    )


# ---- scenario implementations ----
def scenario_resolver_mismatch(txid, qname, client_port, spoof_src, spoof_ans):
    print("[*] resolver_mismatch: send query, then spoof response from different IP")
    q = make_query(txid, qname, src=LOCAL, dst=LOCAL, sport=client_port)
    send_pkt(q)
    time.sleep(0.4)
    ans = DNSRR(rrname=qname, type="A", rdata=spoof_ans, ttl=60)
    resp = make_response(txid, qname, resp_src=spoof_src, resp_dst=LOCAL, resp_dport=client_port, an_rr=ans)
    send_pkt(resp)
    print("[+] done")


def scenario_unsolicited(txid, qname, client_port, spoof_src, spoof_ans):
    print("[*] unsolicited: send a response without any prior query")
    ans = DNSRR(rrname=qname, type="A", rdata=spoof_ans, ttl=60)
    resp = make_response(txid, qname, resp_src=spoof_src, resp_dst=LOCAL, resp_dport=client_port, an_rr=ans)
    send_pkt(resp)
    print("[+] done")


def scenario_txid_mismatch(txid, qname, client_port, spoof_src, spoof_ans):
    print("[*] txid_mismatch: send query with TXID A, response with TXID B")
    tx_query = txid
    tx_resp = (txid + 1) & 0xFFFF
    q = make_query(tx_query, qname, src=LOCAL, dst=LOCAL, sport=client_port)
    send_pkt(q)
    time.sleep(0.3)
    ans = DNSRR(rrname=qname, type="A", rdata=spoof_ans, ttl=60)
    resp = make_response(tx_resp, qname, resp_src=spoof_src, resp_dst=LOCAL, resp_dport=client_port, an_rr=ans)
    send_pkt(resp)
    print(f"[+] sent resp with wrong txid {hex(tx_resp)} (query was {hex(tx_query)})")


def scenario_low_ttl(txid, qname, client_port, spoof_src, spoof_ans):
    print("[*] low_ttl: response with unusually low TTL")
    q = make_query(txid, qname, src=LOCAL, dst=LOCAL, sport=client_port)
    send_pkt(q)
    time.sleep(0.2)
    ans = DNSRR(rrname=qname, type="A", rdata=spoof_ans, ttl=5)  # TTL very low
    resp = make_response(txid, qname, resp_src=spoof_src, resp_dst=LOCAL, resp_dport=client_port, an_rr=ans)
    send_pkt(resp)
    print("[+] done")


def scenario_private_ip(txid, qname, client_port, spoof_src):
    print("[*] private_ip: return a private IP for a public hostname")
    private = "192.168.10.200"
    q = make_query(txid, qname, src=LOCAL, dst=LOCAL, sport=client_port)
    send_pkt(q)
    time.sleep(0.2)
    ans = DNSRR(rrname=qname, type="A", rdata=private, ttl=120)
    resp = make_response(txid, qname, resp_src=spoof_src, resp_dst=LOCAL, resp_dport=client_port, an_rr=ans)
    send_pkt(resp)
    print("[+] done (returned private IP)")


def scenario_conflicting_a(txid, qname, client_port, spoof_src):
    print("[*] conflicting_a: respond with multiple different A records")
    q = make_query(txid, qname, src=LOCAL, dst=LOCAL, sport=client_port)
    send_pkt(q)
    time.sleep(0.25)
    # two different public IPs
    ans1 = DNSRR(rrname=qname, type="A", rdata="203.0.113.10", ttl=300)
    ans2 = DNSRR(rrname=qname, type="A", rdata="198.51.100.77", ttl=300)
    # scapy can put multiple RRs by chaining
    multi_ans = ans1 / ans2
    resp = make_response(txid, qname, resp_src=spoof_src, resp_dst=LOCAL, resp_dport=client_port, an_rr=multi_ans)
    send_pkt(resp)
    print("[+] done (multiple A records sent)")


def scenario_nxdomain(txid, qname, client_port, spoof_src):
    print("[*] nxdomain: send a response with NXDOMAIN (rcode=3)")
    # NXDOMAIN: rcode=3 and no answer
    resp = make_response(txid, qname, resp_src=spoof_src, resp_dst=LOCAL, resp_dport=client_port, an_rr=None, rcode=3)
    send_pkt(resp)
    print("[+] done (NXDOMAIN sent)")


# ---- CLI & dispatch ----
def build_parser():
    p = argparse.ArgumentParser(description="Quick DNS spoof/test scenarios (lab only)")
    p.add_argument("--mode", choices=["resolver_mismatch", "unsolicited", "txid_mismatch", "low_ttl", "private_ip", "conflicting_a", "nxdomain"], required=True)
    p.add_argument("--qname", default=DEFAULT_QNAME)
    p.add_argument("--txid", type=lambda s: int(s, 0), default=None, help="optional txid (hex OK)")
    p.add_argument("--client-port", type=int, default=CLIENT_PORT)
    p.add_argument("--spoof-src", default=DEFAULT_FAKE_RESP_IP)
    p.add_argument("--spoof-ans", default=DEFAULT_FAKE_ANS)
    p.add_argument("--seed", type=int, default=None, help="rng seed (optional)")
    return p


def main():
    need_root()
    p = build_parser()
    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    txid = pick_txid(args.txid)

    print(f"[=] mode={args.mode} qname={args.qname} txid={hex(txid)} client_port={args.client_port}")
    # small dispatch
    if args.mode == "resolver_mismatch":
        scenario_resolver_mismatch(txid, args.qname, args.client_port, args.spoof_src, args.spoof_ans)
    elif args.mode == "unsolicited":
        scenario_unsolicited(txid, args.qname, args.client_port, args.spoof_src, args.spoof_ans)
    elif args.mode == "txid_mismatch":
        scenario_txid_mismatch(txid, args.qname, args.client_port, args.spoof_src, args.spoof_ans)
    elif args.mode == "low_ttl":
        scenario_low_ttl(txid, args.qname, args.client_port, args.spoof_src, args.spoof_ans)
    elif args.mode == "private_ip":
        scenario_private_ip(txid, args.qname, args.client_port, args.spoof_src)
    elif args.mode == "conflicting_a":
        scenario_conflicting_a(txid, args.qname, args.client_port, args.spoof_src)
    elif args.mode == "nxdomain":
        scenario_nxdomain(txid, args.qname, args.client_port, args.spoof_src)
    else:
        print("[!] unknown mode (this should not happen)")

    print("[*] done — check your monitor output (dns_watch or similar).")


if __name__ == "__main__":
    main()

