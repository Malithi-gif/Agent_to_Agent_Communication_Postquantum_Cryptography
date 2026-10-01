import base64
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
KEYS = ROOT / "keys"

def b64e(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def b64d(x: str) -> bytes:
    return base64.b64decode(x.encode("ascii"))

def derive_key(secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"a2a-classical-v1").derive(secret)

def canonical(action, ephemeral_public_b64, nonce_b64, ciphertext_b64):
    return json.dumps({
        "action": action,
        "ephemeral_public": ephemeral_public_b64,
        "nonce": nonce_b64,
        "ciphertext": ciphertext_b64,
    }, sort_keys=True, separators=(",", ":")).encode()

def planner_signer():
    return Ed25519PrivateKey.from_private_bytes(
        (KEYS / "planner_ed25519_private.raw").read_bytes()
    )

def trusted_planner_public():
    return Ed25519PublicKey.from_public_bytes(
        (KEYS / "planner_ed25519_public.raw").read_bytes()
    )

class TargetCrypto:
    def __init__(self):
        start = time.perf_counter_ns()
        self.private = X25519PrivateKey.generate()
        self.public = self.private.public_key()
        self.keygen_ms = (time.perf_counter_ns() - start) / 1e6

    def public_bytes(self):
        return self.public.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def open(self, envelope):
        start = time.perf_counter_ns()
        peer = X25519PublicKey.from_public_bytes(b64d(envelope["ephemeral_public"]))
        secret = self.private.exchange(peer)
        exchange_ms = (time.perf_counter_ns() - start) / 1e6

        msg = canonical(envelope["action"], envelope["ephemeral_public"],
                        envelope["nonce"], envelope["ciphertext"])
        start = time.perf_counter_ns()
        trusted_planner_public().verify(b64d(envelope["signature"]), msg)
        verify_ms = (time.perf_counter_ns() - start) / 1e6

        key = derive_key(secret)
        start = time.perf_counter_ns()
        plain = AESGCM(key).decrypt(
            b64d(envelope["nonce"]),
            b64d(envelope["ciphertext"]),
            envelope["action"].encode(),
        )
        decrypt_ms = (time.perf_counter_ns() - start) / 1e6
        return json.loads(plain), exchange_ms, verify_ms, decrypt_ms

def seal_for_target(action: str, payload: dict, target_public: bytes):
    start = time.perf_counter_ns()
    ephemeral = X25519PrivateKey.generate()
    keygen_ms = (time.perf_counter_ns() - start) / 1e6

    start = time.perf_counter_ns()
    secret = ephemeral.exchange(X25519PublicKey.from_public_bytes(target_public))
    exchange_ms = (time.perf_counter_ns() - start) / 1e6

    key = derive_key(secret)
    nonce = os.urandom(12)
    plain = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    start = time.perf_counter_ns()
    ciphertext = AESGCM(key).encrypt(nonce, plain, action.encode())
    encrypt_ms = (time.perf_counter_ns() - start) / 1e6

    eph_b64 = b64e(ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    nonce_b64 = b64e(nonce)
    ct_b64 = b64e(ciphertext)
    msg = canonical(action, eph_b64, nonce_b64, ct_b64)

    start = time.perf_counter_ns()
    signature = planner_signer().sign(msg)
    sign_ms = (time.perf_counter_ns() - start) / 1e6

    return {
        "action": action,
        "ephemeral_public": eph_b64,
        "nonce": nonce_b64,
        "ciphertext": ct_b64,
        "signature": b64e(signature),
    }, {
        "keygen_ms": keygen_ms,
        "exchange_ms": exchange_ms,
        "sign_ms": sign_ms,
        "encrypt_ms": encrypt_ms,
    }
