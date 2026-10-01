from fastapi import Depends, FastAPI
from pydantic import BaseModel

from agents.logic import flight_response
from security.auth import verify_bearer_token

app = FastAPI(title="Standard TLS Flight Agent")


class FlightRequest(BaseModel):
    origin: str
    destination: str
    date: str


@app.get("/health")
def health():
    return {"agent": "flight", "status": "ok", "tls": True}


@app.post("/search", dependencies=[Depends(verify_bearer_token)])
def search(req: FlightRequest):
    return flight_response(req.model_dump())
