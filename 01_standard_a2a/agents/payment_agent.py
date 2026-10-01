from fastapi import Depends, FastAPI
from pydantic import BaseModel

from agents.logic import payment_response
from security.auth import verify_bearer_token

app = FastAPI(title="Standard TLS Payment Agent")


class PaymentRequest(BaseModel):
    amount: float
    flight_id: str


@app.get("/health")
def health():
    return {"agent": "payment", "status": "ok", "tls": True}


@app.post("/pay", dependencies=[Depends(verify_bearer_token)])
def pay(req: PaymentRequest):
    return payment_response(req.model_dump())
