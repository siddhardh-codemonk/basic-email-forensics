"""
Module 4: DAL System — ties ledger.py + identity.py + anomaly.py together

This is the single entry point you'd import from the dashboard or a demo
script. It handles: registering users, requesting access (signed +
anomaly-checked + written to the ledger), and verifying the whole chain.
"""

import time
from ledger import AccessLedger
from identity import IdentityRegistry
from anomaly import analyze_event


class DALSystem:
    def __init__(self):
        self.ledger = AccessLedger()
        self.identity = IdentityRegistry()

    def register_user(self, user_id: str) -> str:
        return self.identity.register_user(user_id)

    def revoke_user(self, user_id: str):
        self.identity.revoke_user(user_id)

    def request_access(self, user_id: str, resource: str, action: str) -> dict:
        """
        Full flow: build event string -> sign it -> run anomaly checks ->
        write to ledger (even denied/flagged attempts get logged — that's
        the point, you want a record of attempted breaches too).
        """
        timestamp = time.time()
        event_str = f"{user_id}|{resource}|{action}"

        if user_id not in self.identity._keys:
            return {"error": f"Unknown user_id: {user_id} (not registered)"}

        signature = self.identity.sign_event(user_id, event_str)
        analysis = analyze_event(user_id, event_str, signature, timestamp, self.identity)

        event_record = {
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "signature": signature[:32] + "...",  # truncated for readability in the ledger view
            "public_key_fingerprint": self.identity.get_public_fingerprint(user_id),
            "risk_level": analysis["risk_level"],
            "flags": analysis["flags"],
        }

        block = self.ledger.add_event(event_record)

        return {
            "block_index": block.index,
            "block_hash": block.hash,
            "event": event_record,
        }

    def get_chain(self) -> list:
        return self.ledger.to_list()

    def verify_chain(self) -> dict:
        return self.ledger.verify_integrity()

    def simulate_tamper(self, block_index: int, fake_action: str = "ACCESS_GRANTED"):
        original_event = self.ledger.chain[block_index].event
        tampered_event = dict(original_event)
        tampered_event["action"] = fake_action
        tampered_event["flags"] = []  # attacker would also try to hide the flags — demo shows it doesn't matter
        self.ledger.tamper_with_block(block_index, tampered_event)


if __name__ == "__main__":
    import json

    system = DALSystem()

    print("--- Registering users ---")
    print("u001 fingerprint:", system.register_user("u001"))
    print("u002 fingerprint:", system.register_user("u002"))

    print("\n--- Legit access ---")
    r1 = system.request_access("u001", "server-rack-3", "ACCESS_GRANTED")
    print(json.dumps(r1, indent=2))

    print("\n--- Revoke u002, then u002 tries to access anyway ---")
    system.revoke_user("u002")
    r2 = system.request_access("u002", "vault-room", "ACCESS_ATTEMPT")
    print(json.dumps(r2, indent=2))

    print("\n--- Chain integrity BEFORE tampering ---")
    print(system.verify_chain())

    print("\n--- Simulating an attacker editing block 1 directly ---")
    system.simulate_tamper(1, fake_action="ACCESS_GRANTED")

    print("\n--- Chain integrity AFTER tampering ---")
    print(system.verify_chain())
