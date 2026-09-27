"""
Module 2: IP Geolocation + Infrastructure Fingerprinting

Uses ip-api.com (free tier, no key needed, 45 req/min limit) to resolve
an IP to approximate location + hosting/ISP info. Good enough for a
hackathon demo — swap for a paid MaxMind/IPinfo feed for production.
"""

import requests


def geolocate_ip(ip: str) -> dict:
    """Returns location + ISP/org info for an IP, or an error dict."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,regionName,city,isp,org,as,proxy,hosting,query"},
            timeout=5,
        )
        data = resp.json()
        if data.get("status") != "success":
            return {"ip": ip, "error": data.get("message", "lookup failed")}

        return {
            "ip": ip,
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "is_proxy_or_vpn": data.get("proxy", False),
            "is_hosting_provider": data.get("hosting", False),
        }
    except requests.RequestException as e:
        return {"ip": ip, "error": str(e)}


if __name__ == "__main__":
    import sys
    import json

    ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(json.dumps(geolocate_ip(ip), indent=2))
