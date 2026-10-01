from fastapi import Depends, FastAPI
from pydantic import BaseModel

from agents.logic import calendar_response
from security.auth import verify_bearer_token

app = FastAPI(title="Standard TLS Calendar Agent")


class CalendarRequest(BaseModel):
    date: str


@app.get("/health")
def health():
    return {"agent": "calendar", "status": "ok", "tls": True}


@app.post("/check", dependencies=[Depends(verify_bearer_token)])
def check(req: CalendarRequest):
    return calendar_response(req.model_dump())
