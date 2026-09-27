"""
Module 3: Anomaly Detection

Rule-based (same honest approach as the email forensics tool — simple,
explainable rules for a prototype; upgrade path is a trained model on
historical access logs if there's time).
"""

from datetime import datetime


BUSINESS_HOURS = (8, 20)  # 8 AM - 8 PM


def check_revoked_access_attempt(user_id: str, identity_registry) -> bool:
    return identity_registry.is_revoked(user_id)


def check_off_hours(timestamp: float) -> bool:
    hour = datetime.fromtimestamp(timestamp).hour
    return not (BUSINESS_HOURS[0] <= hour < BUSINESS_HOURS[1])


def check_signature_valid(user_id: str, event_str: str, signature: str, identity_registry) -> bool:
    return identity_registry.verify_signature(user_id, event_str, signature)


def analyze_event(user_id: str, event_str: str, signature: str, timestamp: float, identity_registry) -> dict:
    flags = []

    if check_revoked_access_attempt(user_id, identity_registry):
        flags.append(f"REVOKED IDENTITY attempted access: {user_id}")

    if not check_signature_valid(user_id, event_str, signature, identity_registry):
        flags.append(f"INVALID SIGNATURE — event could not be cryptographically verified for {user_id}")

    if check_off_hours(timestamp):
        flags.append(f"Off-hours access attempt (outside {BUSINESS_HOURS[0]}:00-{BUSINESS_HOURS[1]}:00)")

    risk_level = "HIGH" if any("REVOKED" in f or "INVALID SIGNATURE" in f for f in flags) else \
                 "MEDIUM" if flags else "LOW"

    return {"flags": flags, "risk_level": risk_level}
