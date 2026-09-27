"""
Module 5: WHOIS Domain Age Lookup

Newly registered domains are one of the strongest phishing signals there
is — a real brand's domain (paypal.com, microsoft.com) is decades old.
A domain registered last week claiming to be PayPal is a huge red flag.

Falls back gracefully if WHOIS lookup fails (rate-limited, privacy-masked,
or the registrar doesn't respond) — the pipeline should never crash on
this, it should just skip the signal.
"""

import whois
import socket
from datetime import datetime, timezone


def get_domain_age_days(domain: str, timeout_seconds: int = 6) -> dict:
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_seconds)
    try:
        w = whois.whois(domain)
        creation = w.creation_date

        # python-whois sometimes returns a list of dates instead of one
        if isinstance(creation, list):
            creation = creation[0]

        if creation is None:
            return {"domain": domain, "error": "no creation date returned (privacy-masked or lookup failed)"}

        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation).days

        return {
            "domain": domain,
            "creation_date": creation.isoformat(),
            "age_days": age_days,
            "is_newly_registered": age_days < 90,  # <90 days = high suspicion threshold
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)}
    finally:
        socket.setdefaulttimeout(original_timeout)


if __name__ == "__main__":
    import sys
    import json

    domain = sys.argv[1] if len(sys.argv) > 1 else "google.com"
    print(json.dumps(get_domain_age_days(domain), indent=2))
