from fastapi import FastAPI, HTTPException, Query
from agents.logic import flight_response
from security.pqc import PQCTarget

app = FastAPI(title="Adaptive PQC Flight Agent")
crypto = PQCTarget(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])

@app.get("/health")
def health():
    return {"agent": "flight", "status": "ok"}

@app.get("/crypto/public")
def public_key(kem: str = Query(...)):
    try:
        return crypto.public_info(kem)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/search")
def secure_call(envelope: dict):
    try:
        payload, decap_ms, verify_ms, decrypt_ms = crypto.open(
            envelope,
            signature_required=envelope.get("sig_alg") is not None,
        )
        result = flight_response(payload)
        result["crypto_metrics"] = {
            "decap_or_exchange_ms": decap_ms,
            "verify_ms": verify_ms,
            "decrypt_ms": decrypt_ms,
        }
        return result
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
