"""
SIH26 - Decentralized Access Ledger (DAL)
Module 1: Hash-Chain Ledger

HONEST SCOPING NOTE (say this in the pitch, don't hide it):
This is a single-node hash-chain, demonstrating blockchain's core
tamper-evidence mechanism (each block cryptographically linked to the
previous one). It is NOT a distributed multi-node network with
consensus — that would be a production deployment on Hyperledger
Fabric across BEL's actual infrastructure nodes. What this prototype
proves is the DATA STRUCTURE and TAMPER-DETECTION logic, which is the
part that matters for the demo.
"""

import hashlib
import json
import time
from dataclasses import dataclass, asdict, field


@dataclass
class Block:
    index: int
    timestamp: float
    event: dict          # the actual access event: {user_id, resource, action, signature}
    prev_hash: str
    hash: str = field(default="")

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "event": self.event,
            "prev_hash": self.prev_hash,
        }
        payload_str = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(payload_str.encode()).hexdigest()


class AccessLedger:
    def __init__(self):
        self.chain: list[Block] = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(
            index=0,
            timestamp=time.time(),
            event={"type": "GENESIS", "note": "Ledger initialized"},
            prev_hash="0" * 64,
        )
        genesis.hash = genesis.compute_hash()
        self.chain.append(genesis)

    def add_event(self, event: dict) -> Block:
        """
        event should be a dict like:
        {"user_id": "u123", "resource": "server-rack-3", "action": "ACCESS_GRANTED",
         "signature": "<hex sig>", "public_key_fingerprint": "<hex>"}
        """
        prev_block = self.chain[-1]
        new_block = Block(
            index=prev_block.index + 1,
            timestamp=time.time(),
            event=event,
            prev_hash=prev_block.hash,
        )
        new_block.hash = new_block.compute_hash()
        self.chain.append(new_block)
        return new_block

    def verify_integrity(self) -> dict:
        """
        Walks the whole chain and checks:
        1. Each block's stored hash matches a fresh recomputation (detects
           direct tampering with block content)
        2. Each block's prev_hash matches the actual previous block's hash
           (detects reordering / deletion)

        Returns which block index broke, if any.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            recomputed = current.compute_hash()
            if current.hash != recomputed:
                return {
                    "valid": False,
                    "broken_at_index": current.index,
                    "reason": f"Block {current.index} content was altered — stored hash doesn't match recomputed hash",
                }

            if current.prev_hash != previous.hash:
                return {
                    "valid": False,
                    "broken_at_index": current.index,
                    "reason": f"Block {current.index}'s prev_hash doesn't match block {previous.index}'s actual hash — chain link broken",
                }

        return {"valid": True, "broken_at_index": None, "reason": "Chain intact — no tampering detected"}

    def tamper_with_block(self, index: int, new_event: dict):
        """
        FOR DEMO PURPOSES ONLY — simulates an attacker/rogue-admin editing
        a past record directly (bypassing add_event, which is what a real
        attacker with DB access would do). Use this live on stage, then
        call verify_integrity() to show it gets caught.
        """
        if 0 <= index < len(self.chain):
            self.chain[index].event = new_event
            # NOTE: we deliberately do NOT recompute the hash here —
            # that's the point. A real tamper attempt wouldn't know to
            # recompute it either, which is exactly what verify_integrity() catches.

    def to_list(self) -> list:
        return [asdict(b) for b in self.chain]


if __name__ == "__main__":
    ledger = AccessLedger()

    ledger.add_event({"user_id": "u001", "resource": "server-rack-3", "action": "ACCESS_GRANTED"})
    ledger.add_event({"user_id": "u002", "resource": "vault-room", "action": "ACCESS_DENIED"})
    ledger.add_event({"user_id": "u001", "resource": "server-rack-3", "action": "ACCESS_REVOKED"})

    print("Chain length:", len(ledger.chain))
    print("Integrity check (should be valid):", ledger.verify_integrity())

    print("\n--- Simulating tampering with block 1 ---")
    ledger.tamper_with_block(1, {"user_id": "u002", "resource": "vault-room", "action": "ACCESS_GRANTED"})
    print("Integrity check (should now FAIL):", ledger.verify_integrity())
