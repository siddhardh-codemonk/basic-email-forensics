"""
Module 4: Risk Scoring Engine

Combines signals from header_parser, geolocate, and phishing_language into
a single 0-100 fraud risk score + verdict. Weights are illustrative for
the prototype — tune them against a labeled dataset if you want to defend
the scoring methodology at evaluation.
"""

from header_parser import analyze_eml
from geolocate import geolocate_ip
from phishing_language import analyze_language
from domain_age import get_domain_age_days


WEIGHTS = {
    "spf_fail": 18,
    "dkim_fail_or_none": 12,
    "dmarc_fail": 18,
    "sender_mismatch_per_flag": 8,    # capped at 2 flags = 16 max
    "urgency_phrase_per_hit": 3,       # capped at 5 hits = 15 max
    "credential_harvest_per_hit": 7,   # capped at 2 hits = 14 max
    "brand_impersonation_per_hit": 22,  # typosquat/unrelated-domain brand mentions are a strong signal
    "hosting_provider_origin": 8,      # mail claiming to be a brand but sent from generic hosting
    "proxy_or_vpn_origin": 6,
    "newly_registered_domain": 15,     # from_domain registered < 90 days ago
}


def score_email(eml_path: str, email_body_text: str = "") -> dict:
    parsed = analyze_eml(eml_path)
    auth = parsed["auth_results"]
    mismatch = parsed["sender_mismatch"]
    origin_ip = parsed["originating_ip"]

    subject = parsed["headers"]["Subject"] or ""
    from_domain = mismatch["from_domain"]

    language = analyze_language(subject, email_body_text, from_domain)

    geo = geolocate_ip(origin_ip) if origin_ip else {"error": "no originating IP found"}
    domain_age = get_domain_age_days(from_domain) if from_domain else {"error": "no from_domain found"}

    score = 0
    reasons = []

    if auth.get("spf") == "fail":
        score += WEIGHTS["spf_fail"]
        reasons.append("SPF check failed")

    if auth.get("dkim") in ("fail", "none", None):
        score += WEIGHTS["dkim_fail_or_none"]
        reasons.append(f"DKIM result: {auth.get('dkim')}")

    if auth.get("dmarc") == "fail":
        score += WEIGHTS["dmarc_fail"]
        reasons.append("DMARC check failed")

    mismatch_count = min(len(mismatch["mismatch_flags"]), 2)
    if mismatch_count:
        score += mismatch_count * WEIGHTS["sender_mismatch_per_flag"]
        reasons.extend(mismatch["mismatch_flags"])

    urgency_count = min(len(language["urgency_phrases_found"]), 5)
    if urgency_count:
        score += urgency_count * WEIGHTS["urgency_phrase_per_hit"]
        reasons.append(f"{urgency_count} urgency/pressure phrase(s) found")

    cred_count = min(len(language["credential_harvest_phrases_found"]), 2)
    if cred_count:
        score += cred_count * WEIGHTS["credential_harvest_per_hit"]
        reasons.append(f"{cred_count} credential-harvesting phrase(s) found")

    if language["brand_impersonation_flags"]:
        score += WEIGHTS["brand_impersonation_per_hit"]
        reasons.extend(language["brand_impersonation_flags"])

    if not geo.get("error"):
        if geo.get("is_hosting_provider"):
            score += WEIGHTS["hosting_provider_origin"]
            reasons.append(f"Origin IP is a hosting/datacenter provider ({geo.get('isp')}), not a typical mail server")
        if geo.get("is_proxy_or_vpn"):
            score += WEIGHTS["proxy_or_vpn_origin"]
            reasons.append("Origin IP flagged as proxy/VPN")

    if not domain_age.get("error") and domain_age.get("is_newly_registered"):
        score += WEIGHTS["newly_registered_domain"]
        reasons.append(f"Sender domain registered only {domain_age['age_days']} days ago")

    score = min(score, 100)

    if score >= 70:
        verdict = "HIGH RISK - likely phishing/fraud"
    elif score >= 40:
        verdict = "MEDIUM RISK - suspicious, needs review"
    else:
        verdict = "LOW RISK - likely legitimate"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
        "auth_results": auth,
        "sender_mismatch": mismatch,
        "language_signals": language,
        "originating_ip": origin_ip,
        "geolocation": geo,
        "domain_age": domain_age,
        "hop_count": len(parsed["relay_chain"]),
        "relay_chain": parsed["relay_chain"],
    }


if __name__ == "__main__":
    import sys
    import json

    path = sys.argv[1] if len(sys.argv) > 1 else "sample_emails/phishing_sample.eml"
    body = "Click here to verify: http://paypa1-verify.com/secure/login We have detected unusual activity."
    result = score_email(path, body)
    print(json.dumps({k: v for k, v in result.items() if k != "relay_chain"}, indent=2))
