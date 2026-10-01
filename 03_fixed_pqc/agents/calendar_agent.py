from fastapi import FastAPI, HTTPException, Query
from agents.logic import calendar_response
from security.pqc import PQCTarget

app = FastAPI(title="Fixed PQC Calendar Agent")
crypto = PQCTarget(["ML-KEM-768"])

@app.get("/health")
def health():
    return {"agent": "calendar", "status": "ok"}

@app.get("/crypto/public")
def public_key(kem: str = Query(...)):
    try:
        return crypto.public_info(kem)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/check")
def secure_call(envelope: dict):
    try:
        payload, decap_ms, verify_ms, decrypt_ms = crypto.open(
            envelope,
            signature_required=True,
        )
        result = calendar_response(payload)
        result["crypto_metrics"] = {
            "decap_or_exchange_ms": decap_ms,
            "verify_ms": verify_ms,
            "decrypt_ms": decrypt_ms,
        }
        return result
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
