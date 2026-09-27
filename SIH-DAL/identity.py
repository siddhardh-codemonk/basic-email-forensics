"""
Module 2: Identity Layer

Each user gets an RSA keypair. Access events are signed with the user's
private key — so the ledger doesn't just say "u001 accessed vault-room",
it PROVES u001 (or whoever holds their private key) authorized it.
Nobody can forge an event on someone else's behalf without their key.

For the prototype, keys are generated and held in-memory (a dict acting
as a mock identity registry). Production version: keys would be issued
via a real PKI / HSM, not generated ad-hoc like this.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import hashlib


class IdentityRegistry:
    def __init__(self):
        self._keys = {}  # user_id -> {"private": key, "public": key}
        self._revoked = set()

    def register_user(self, user_id: str):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        self._keys[user_id] = {"private": private_key, "public": public_key}
        return self.get_public_fingerprint(user_id)

    def revoke_user(self, user_id: str):
        self._revoked.add(user_id)

    def is_revoked(self, user_id: str) -> bool:
        return user_id in self._revoked

    def get_public_fingerprint(self, user_id: str) -> str:
        """Short hash of the public key — used as a display identifier."""
        pub = self._keys[user_id]["public"]
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(pub_bytes).hexdigest()[:16]

    def sign_event(self, user_id: str, event_data: str) -> str:
        private_key = self._keys[user_id]["private"]
        signature = private_key.sign(
            event_data.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return signature.hex()

    def verify_signature(self, user_id: str, event_data: str, signature_hex: str) -> bool:
        try:
            public_key = self._keys[user_id]["public"]
            public_key.verify(
                bytes.fromhex(signature_hex),
                event_data.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


if __name__ == "__main__":
    registry = IdentityRegistry()

    fp = registry.register_user("u001")
    print("u001 public key fingerprint:", fp)

    event_str = "u001|server-rack-3|ACCESS_GRANTED"
    sig = registry.sign_event("u001", event_str)
    print("Signature (truncated):", sig[:40], "...")

    print("Verify with correct data:", registry.verify_signature("u001", event_str, sig))
    print("Verify with tampered data:", registry.verify_signature("u001", "u001|vault-room|ACCESS_GRANTED", sig))

    registry.revoke_user("u001")
    print("u001 revoked:", registry.is_revoked("u001"))
