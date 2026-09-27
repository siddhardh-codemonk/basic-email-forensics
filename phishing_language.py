"""
Module 3: Phishing Language Detection (rule-based baseline)

For the prototype, keyword/pattern matching is enough to demo the concept
and score reasonably well on obvious phishing. If you have time after the
core pipeline works, swap detect_urgency_cues() for a small fine-tuned
classifier (e.g. sklearn TF-IDF + logistic regression on a phishing email
dataset from Kaggle) — same output shape, drop-in replacement.
"""

import re

URGENCY_PHRASES = [
    r"urgent", r"immediately", r"act now", r"24 hours", r"suspend(ed)?",
    r"verify (your|now)", r"account.{0,15}(locked|suspended|compromised)",
    r"click here", r"failure to act", r"final notice", r"limited time",
    r"unusual activity", r"confirm your (identity|account|password)",
]

CREDENTIAL_HARVEST_PHRASES = [
    r"enter your password", r"login (below|now)", r"update your (billing|payment)",
    r"social security", r"bank details", r"card number", r"cvv",
]

# brand name -> their actual official domain(s). Extend this list as needed.
KNOWN_BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "netflix": ["netflix.com"],
}


def find_matches(text: str, patterns: list) -> list:
    text_lower = text.lower()
    hits = []
    for p in patterns:
        if re.search(p, text_lower):
            hits.append(p)
    return hits


def check_brand_domain_mismatch(subject: str, body: str, from_domain: str) -> list:
    """
    Two distinct impersonation patterns, both checked:

    1. Email talks about a brand, sender domain has NOTHING to do with it
       e.g. "PayPal" mentioned, sending domain is "free-hosting.net"

    2. Email talks about a brand, sender domain CONTAINS the brand name
       but ISN'T the brand's real domain (typosquat / lookalike)
       e.g. "Microsoft" mentioned, sending from "microsoft-support.co"
       This is actually the MORE common real-world pattern and a naive
       substring check misses it entirely — don't just check "brand not
       in domain", check "domain not in official domain list".
    """
    combined = (subject + " " + body).lower()
    from_domain_lower = from_domain.lower()
    flags = []

    for brand, official_domains in KNOWN_BRAND_DOMAINS.items():
        if brand not in combined:
            continue

        is_official = from_domain_lower in official_domains
        if is_official:
            continue

        if brand in from_domain_lower:
            flags.append(
                f"Sender domain '{from_domain}' contains brand name '{brand}' "
                f"but is NOT an official {brand} domain (typosquat pattern)"
            )
        else:
            flags.append(
                f"Mentions '{brand}' but sender domain '{from_domain}' is unrelated to {brand}"
            )

    return flags


def analyze_language(subject: str, body: str, from_domain: str) -> dict:
    urgency_hits = find_matches(subject + " " + body, URGENCY_PHRASES)
    credential_hits = find_matches(body, CREDENTIAL_HARVEST_PHRASES)
    brand_flags = check_brand_domain_mismatch(subject, body, from_domain)

    return {
        "urgency_phrases_found": urgency_hits,
        "credential_harvest_phrases_found": credential_hits,
        "brand_impersonation_flags": brand_flags,
    }


if __name__ == "__main__":
    sample_subject = "URGENT: Your account will be suspended in 24 hours - Verify Now"
    sample_body = "Click here to verify: http://paypa1-verify.com/secure/login"
    import json
    print(json.dumps(analyze_language(sample_subject, sample_body, "paypa1-verify.com"), indent=2))
