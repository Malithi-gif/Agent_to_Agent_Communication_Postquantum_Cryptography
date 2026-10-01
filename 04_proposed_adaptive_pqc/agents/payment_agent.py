import json
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Query
import oqs

from agents.logic import payment_response
from security.pqc import PQCTarget, b64d, load_sig_public

app = FastAPI(title="Adaptive PQC Payment Agent")
crypto = PQCTarget(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])

@app.get("/health")
def health():
    return {"agent": "payment", "status": "ok"}

@app.get("/crypto/public")
def public_key(kem: str = Query(...)):
    try:
        return crypto.public_info(kem)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

def verify_delegation(token, payload):
    claims = token["claims"]
    body = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    with oqs.Signature("ML-DSA-87") as verifier:
        valid = verifier.verify(
            body,
            b64d(token["signature"]),
            load_sig_public("ML-DSA-87"),
        )
    if not valid:
        raise ValueError("Invalid delegation signature")
    if claims["destination"] != "payment" or claims["action"] != "payment":
        raise ValueError("Delegation scope mismatch")
    if claims.get("max_amount") is not None:
        if float(payload["amount"]) > float(claims["max_amount"]):
            raise ValueError("Payment exceeds delegation limit")
    if datetime.fromisoformat(claims["expires_at"]) < datetime.now(timezone.utc):
        raise ValueError("Delegation expired")

@app.post("/pay")
def pay(envelope: dict):
    try:
        payload, decap_ms, verify_ms, decrypt_ms = crypto.open(
            envelope,
            signature_required=envelope.get("sig_alg") is not None,
        )
        token = payload.get("delegation_token")
        if not token:
            raise ValueError("Critical payment requires delegation token")
        verify_delegation(token, payload)

        result = payment_response(payload)
        result["crypto_metrics"] = {
            "decap_or_exchange_ms": decap_ms,
            "verify_ms": verify_ms,
            "decrypt_ms": decrypt_ms,
        }
        return result
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
