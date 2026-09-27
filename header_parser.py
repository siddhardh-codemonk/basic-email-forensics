"""
SIH26106 - Email Threat Detection, GeoLocation & Forensic Intelligence Platform
Module 1: Header Parser + Auth Result Extraction

Parses a raw .eml file and pulls out everything the risk scorer needs:
- Received chain (relay hops, in order of transit)
- SPF / DKIM / DMARC verdicts (from Authentication-Results, if present)
- From / Reply-To / Return-Path mismatch detection
- Originating IPs per hop
"""

import email
from email import policy
from email.parser import BytesParser
import re
import ipaddress


IP_REGEX = re.compile(
    r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?'
)


def load_eml(path: str):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def extract_headers(msg) -> dict:
    """Pull the headers relevant to forensic tracing."""
    return {
        "From": msg.get("From", ""),
        "Reply-To": msg.get("Reply-To", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Subject": msg.get("Subject", ""),
        "Message-ID": msg.get("Message-ID", ""),
        "Date": msg.get("Date", ""),
        "Authentication-Results": msg.get_all("Authentication-Results", []),
        "Received-SPF": msg.get_all("Received-SPF", []),
        "Received": msg.get_all("Received", []),
    }


def extract_relay_chain(received_headers: list) -> list:
    """
    Received headers are stacked newest-first (top of the email = last hop
    it went through before reaching you). We reverse them so hop[0] is the
    ORIGINATING server — the one most useful for tracing the sender.
    """
    hops = []
    for i, raw in enumerate(received_headers):
        ips = IP_REGEX.findall(raw)
        # filter out obviously private/reserved IPs (internal relay noise)
        public_ips = []
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
                    public_ips.append(ip)
            except ValueError:
                continue
        hops.append({
            "hop_index": i,
            "raw": raw.strip().replace("\n", " ").replace("\t", " "),
            "ips_found": ips,
            "public_ips": public_ips,
        })
    hops.reverse()  # oldest (originating) hop first
    return hops


def parse_auth_results(auth_headers: list) -> dict:
    """
    Extract spf=, dkim=, dmarc= verdicts from Authentication-Results header(s).
    Real-world emails can have multiple Authentication-Results headers
    (one per receiving MTA) — we take the first PASS/FAIL we find for each.
    """
    verdicts = {"spf": None, "dkim": None, "dmarc": None}
    combined = " ".join(auth_headers)

    for mechanism in verdicts:
        match = re.search(rf'{mechanism}=(\w+)', combined, re.IGNORECASE)
        if match:
            verdicts[mechanism] = match.group(1).lower()

    return verdicts


def get_originating_ip(hops: list) -> str | None:
    """First public IP found in the earliest (originating) hop."""
    for hop in hops:
        if hop["public_ips"]:
            return hop["public_ips"][0]
    return None


def check_sender_mismatch(headers: dict) -> dict:
    """
    Flags classic spoofing tell: From / Reply-To / Return-Path domains
    don't line up. Legit mail from a real org usually has these aligned
    (or Reply-To intentionally different for a known reason, e.g. no-reply@).
    """
    def domain_of(addr: str) -> str:
        m = re.search(r'@([\w.-]+)', addr or "")
        return m.group(1).lower() if m else ""

    from_domain = domain_of(headers["From"])
    reply_domain = domain_of(headers["Reply-To"])
    return_domain = domain_of(headers["Return-Path"])

    mismatch_flags = []
    if reply_domain and reply_domain != from_domain:
        mismatch_flags.append(f"Reply-To domain ({reply_domain}) != From domain ({from_domain})")
    if return_domain and return_domain != from_domain:
        mismatch_flags.append(f"Return-Path domain ({return_domain}) != From domain ({from_domain})")

    return {
        "from_domain": from_domain,
        "reply_domain": reply_domain,
        "return_domain": return_domain,
        "mismatch_flags": mismatch_flags,
    }


def analyze_eml(path: str) -> dict:
    """Full pipeline: load -> parse headers -> relay chain -> auth -> mismatch."""
    msg = load_eml(path)
    headers = extract_headers(msg)
    hops = extract_relay_chain(headers["Received"])
    auth = parse_auth_results(headers["Authentication-Results"])
    mismatch = check_sender_mismatch(headers)
    origin_ip = get_originating_ip(hops)

    return {
        "headers": headers,
        "relay_chain": hops,
        "auth_results": auth,
        "sender_mismatch": mismatch,
        "originating_ip": origin_ip,
    }


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python3 header_parser.py <path-to-email.eml>")
        sys.exit(1)

    result = analyze_eml(sys.argv[1])
    # Received list is verbose — trim for readable console output
    printable = {
        "from": result["headers"]["From"],
        "subject": result["headers"]["Subject"],
        "auth_results": result["auth_results"],
        "sender_mismatch": result["sender_mismatch"],
        "originating_ip": result["originating_ip"],
        "hop_count": len(result["relay_chain"]),
    }
    print(json.dumps(printable, indent=2))
