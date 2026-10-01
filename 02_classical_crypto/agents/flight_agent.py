from fastapi import FastAPI, HTTPException
from agents.logic import flight_response
from security.classical import TargetCrypto, b64e

app = FastAPI(title="Classical Flight Agent")
crypto = TargetCrypto()

@app.get("/health")
def health():
    return {"agent": "flight", "status": "ok"}

@app.get("/crypto/public")
def public_key():
    return {
        "algorithm": "X25519",
        "public_key": b64e(crypto.public_bytes()),
        "keygen_ms": crypto.keygen_ms,
    }

@app.post("/search")
def secure_call(envelope: dict):
    try:
        payload, exchange_ms, verify_ms, decrypt_ms = crypto.open(envelope)
        result = flight_response(payload)
        result["crypto_metrics"] = {
            "decap_or_exchange_ms": exchange_ms,
            "verify_ms": verify_ms,
            "decrypt_ms": decrypt_ms,
        }
        return result
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
