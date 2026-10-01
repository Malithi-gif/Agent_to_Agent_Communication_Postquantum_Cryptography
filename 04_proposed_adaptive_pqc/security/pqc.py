import base64
import json
import os
import time
from pathlib import Path

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[1]
KEYS = ROOT / "keys"

def b64e(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")

def b64d(x: str) -> bytes:
    return base64.b64decode(x.encode("ascii"))

def derive_key(secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)

def canonical_for_signature(action, kem_alg, ciphertext_b64, nonce_b64, encrypted_payload_b64):
    return json.dumps({
        "action": action,
        "kem_alg": kem_alg,
        "kem_ciphertext": ciphertext_b64,
        "nonce": nonce_b64,
        "encrypted_payload": encrypted_payload_b64,
    }, sort_keys=True, separators=(",", ":")).encode()

def load_sig_secret(sig_alg):
    safe = sig_alg.replace("-", "_")
    return (KEYS / f"planner_{safe}_secret.bin").read_bytes()

def load_sig_public(sig_alg):
    safe = sig_alg.replace("-", "_")
    return (KEYS / f"planner_{safe}_public.bin").read_bytes()

class PQCTarget:
    def __init__(self, kem_algs):
        self.kems = {}
        self.public_keys = {}
        self.keygen_ms = {}
        for alg in kem_algs:
            kem = oqs.KeyEncapsulation(alg)
            start = time.perf_counter_ns()
            pk = kem.generate_keypair()
            elapsed = (time.perf_counter_ns() - start) / 1e6
            self.kems[alg] = kem
            self.public_keys[alg] = pk
            self.keygen_ms[alg] = elapsed

    def public_info(self, kem_alg):
        if kem_alg not in self.kems:
            raise ValueError(f"Unsupported KEM: {kem_alg}")
        return {
            "kem_alg": kem_alg,
            "public_key": b64e(self.public_keys[kem_alg]),
            "keygen_ms": self.keygen_ms[kem_alg],
        }

    def open(self, envelope, signature_required=True):
        kem_alg = envelope["kem_alg"]
        kem = self.kems[kem_alg]

        start = time.perf_counter_ns()
        secret = kem.decap_secret(b64d(envelope["kem_ciphertext"]))
        decap_ms = (time.perf_counter_ns() - start) / 1e6

        verify_ms = 0.0
        sig_alg = envelope.get("sig_alg")
        if signature_required:
            msg = canonical_for_signature(
                envelope["action"], kem_alg, envelope["kem_ciphertext"],
                envelope["nonce"], envelope["encrypted_payload"]
            )
            with oqs.Signature(sig_alg) as verifier:
                start = time.perf_counter_ns()
                valid = verifier.verify(
                    msg,
                    b64d(envelope["signature"]),
                    load_sig_public(sig_alg),
                )
                verify_ms = (time.perf_counter_ns() - start) / 1e6
            if not valid:
                raise ValueError("ML-DSA signature verification failed")

        key = derive_key(secret, f"a2a-{kem_alg}".encode())
        start = time.perf_counter_ns()
        plain = AESGCM(key).decrypt(
            b64d(envelope["nonce"]),
            b64d(envelope["encrypted_payload"]),
            envelope["action"].encode(),
        )
        decrypt_ms = (time.perf_counter_ns() - start) / 1e6

        return json.loads(plain), decap_ms, verify_ms, decrypt_ms

def seal_for_target(action, payload, target_public, kem_alg, sig_alg=None):
    with oqs.KeyEncapsulation(kem_alg) as encapsulator:
        start = time.perf_counter_ns()
        kem_ciphertext, secret = encapsulator.encap_secret(target_public)
        encap_ms = (time.perf_counter_ns() - start) / 1e6

    key = derive_key(secret, f"a2a-{kem_alg}".encode())
    nonce = os.urandom(12)
    plain = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    start = time.perf_counter_ns()
    encrypted = AESGCM(key).encrypt(nonce, plain, action.encode())
    encrypt_ms = (time.perf_counter_ns() - start) / 1e6

    envelope = {
        "action": action,
        "kem_alg": kem_alg,
        "kem_ciphertext": b64e(kem_ciphertext),
        "nonce": b64e(nonce),
        "encrypted_payload": b64e(encrypted),
        "sig_alg": sig_alg,
        "signature": "",
    }

    sign_ms = 0.0
    if sig_alg:
        msg = canonical_for_signature(
            action, kem_alg, envelope["kem_ciphertext"],
            envelope["nonce"], envelope["encrypted_payload"]
        )
        with oqs.Signature(sig_alg, load_sig_secret(sig_alg)) as signer:
            start = time.perf_counter_ns()
            signature = signer.sign(msg)
            sign_ms = (time.perf_counter_ns() - start) / 1e6
        envelope["signature"] = b64e(signature)

    return envelope, {
        "encap_ms": encap_ms,
        "sign_ms": sign_ms,
        "encrypt_ms": encrypt_ms,
    }
