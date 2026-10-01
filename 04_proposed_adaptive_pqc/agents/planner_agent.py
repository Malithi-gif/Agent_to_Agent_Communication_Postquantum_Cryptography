import json
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx
import psutil
import oqs
from fastapi import FastAPI
from pydantic import BaseModel

from config import AGENTS, MAX_BOOKING_PRICE
from metrics.collector import append_metric, process_memory_mb
from security.risk import classify_risk
from security.pqc import (
    seal_for_target,
    b64d,
    b64e,
    load_sig_secret,
)


app = FastAPI(title="Proposed Adaptive PQC Planner")

AUDIT_FILE = (
    Path(__file__).resolve().parents[1]
    / "audit"
    / "audit.jsonl"
)


POLICY = {
    "LOW": {
        "kem": "ML-KEM-512",
        "sig": None,
        "delegation": False,
        "audit": False,
    },

    "MEDIUM": {
        "kem": "ML-KEM-768",
        "sig": "ML-DSA-65",
        "delegation": False,
        "audit": True,
    },

    "CRITICAL": {
        "kem": "ML-KEM-1024",
        "sig": "ML-DSA-87",
        "delegation": True,
        "audit": True,
    },
}


class TravelTask(BaseModel):
    origin: str = "ORD"
    destination: str = "JFK"
    date: str
    max_price: float = MAX_BOOKING_PRICE
    auto_book: bool = True


def decoded_size(value):
    """
    Return the raw byte size of a Base64-encoded object.
    """

    if not value:
        return 0

    try:
        return len(b64d(value))
    except Exception:
        return 0


def find_decoded_size(envelope, possible_names):
    """
    Search several possible field names in the PQC envelope.
    """

    for name in possible_names:

        if name in envelope:

            size = decoded_size(
                envelope.get(name)
            )

            if size > 0:
                return size

    return 0


def make_delegation(
    task_id,
    destination,
    action,
    amount=None,
):

    claims = {
        "task_id": task_id,
        "destination": destination,
        "action": action,
        "max_amount": amount,

        "expires_at": (
            datetime.now(timezone.utc)
            + timedelta(minutes=5)
        ).isoformat(),

        "nonce": uuid.uuid4().hex,
    }

    body = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    with oqs.Signature(
        "ML-DSA-87",
        load_sig_secret("ML-DSA-87"),
    ) as signer:

        signature = signer.sign(
            body
        )

    return {
        "claims": claims,
        "sig_alg": "ML-DSA-87",
        "signature": b64e(signature),
    }


def write_audit(record):

    AUDIT_FILE.parent.mkdir(
        exist_ok=True
    )

    with AUDIT_FILE.open(
        "a",
        encoding="utf-8",
    ) as f:

        f.write(
            json.dumps(
                record,
                sort_keys=True,
            )
            + "\n"
        )


async def call_agent(
    task_id,
    destination,
    action,
    endpoint,
    payload,
):

    risk = classify_risk(
        action
    )

    policy = POLICY[
        risk
    ]

    delegation_bytes = 0

    payload = dict(
        payload
    )

    # =========================================================
    # Delegation only for CRITICAL risk
    # =========================================================

    if policy["delegation"]:

        token = make_delegation(
            task_id,
            destination,
            action,
            payload.get("amount"),
        )

        payload[
            "delegation_token"
        ] = token

        delegation_bytes = len(
            json.dumps(
                token,
                separators=(",", ":"),
            ).encode("utf-8")
        )

    total_start = time.perf_counter()

    success = False
    response_bytes = 0

    m = {
        "keygen_ms": 0,
        "encap_ms": 0,
        "decap_ms": 0,
        "sign_ms": 0,
        "verify_ms": 0,
        "encrypt_ms": 0,
        "decrypt_ms": 0,

        "request_ms": 0,
        "request_bytes": 0,

        # NEW crypto-size fields
        "public_key_bytes": 0,
        "kem_ciphertext_bytes": 0,
        "signature_bytes": 0,
        "encrypted_payload_bytes": 0,
    }

    try:

        async with httpx.AsyncClient(
            timeout=60.0
        ) as client:

            # =================================================
            # Get risk-selected ML-KEM public key
            # =================================================

            kr = await client.get(
                AGENTS[destination]["url"]
                + "/crypto/public",

                params={
                    "kem":
                        policy["kem"]
                },
            )

            kr.raise_for_status()

            ki = kr.json()

            target_public_key = b64d(
                ki["public_key"]
            )

            # Raw ML-KEM public key size
            m["public_key_bytes"] = len(
                target_public_key
            )

            # =================================================
            # Protect request using adaptive PQC policy
            # =================================================

            envelope, c = seal_for_target(
                action,
                payload,
                target_public_key,
                policy["kem"],
                policy["sig"],
            )

            # =================================================
            # Crypto-object-size measurements
            # =================================================

            m["kem_ciphertext_bytes"] = c.get(
                "kem_ciphertext_bytes",
                0,
            )

            m["signature_bytes"] = c.get(
                "signature_bytes",
                0,
            )

            m["encrypted_payload_bytes"] = c.get(
                "encrypted_payload_bytes",
                0,
            )

            # -------------------------------------------------
            # Fallback if security/pqc.py does not return sizes
            # -------------------------------------------------

            if m["kem_ciphertext_bytes"] == 0:

                m["kem_ciphertext_bytes"] = (
                    find_decoded_size(
                        envelope,
                        [
                            "kem_ciphertext",
                            "kem_ct",
                            "kem_cipher",
                            "encapsulation",
                            "encap",
                        ],
                    )
                )

            if m["signature_bytes"] == 0:

                m["signature_bytes"] = (
                    find_decoded_size(
                        envelope,
                        [
                            "signature",
                            "sig",
                            "ml_dsa_signature",
                        ],
                    )
                )

            if m["encrypted_payload_bytes"] == 0:

                m["encrypted_payload_bytes"] = (
                    find_decoded_size(
                        envelope,
                        [
                            "ciphertext",
                            "encrypted_payload",
                            "payload_ciphertext",
                            "ct",
                        ],
                    )
                )

            # LOW risk intentionally has no ML-DSA signature
            if policy["sig"] is None:
                m["signature_bytes"] = 0

            # =================================================
            # Serialized request size
            # =================================================

            request_bytes = len(
                json.dumps(
                    envelope,
                    separators=(",", ":"),
                ).encode("utf-8")
            )

            # =================================================
            # Send request
            # =================================================

            rs = time.perf_counter()

            r = await client.post(
                AGENTS[destination]["url"]
                + endpoint,

                json=envelope,
            )

            request_ms = (
                time.perf_counter()
                - rs
            ) * 1000

            r.raise_for_status()

            response_bytes = len(
                r.content
            )

            result = r.json()

            s = result.pop(
                "crypto_metrics",
                {},
            )

            # =================================================
            # Save crypto timings
            # =================================================

            m.update({

                "keygen_ms":
                    ki.get(
                        "keygen_ms",
                        0,
                    ),

                "encap_ms":
                    c.get(
                        "encap_ms",
                        0,
                    ),

                "decap_ms":
                    s.get(
                        "decap_or_exchange_ms",
                        0,
                    ),

                "sign_ms":
                    c.get(
                        "sign_ms",
                        0,
                    ),

                "verify_ms":
                    s.get(
                        "verify_ms",
                        0,
                    ),

                "encrypt_ms":
                    c.get(
                        "encrypt_ms",
                        0,
                    ),

                "decrypt_ms":
                    s.get(
                        "decrypt_ms",
                        0,
                    ),

                "request_ms":
                    request_ms,

                "request_bytes":
                    request_bytes,
            })

            success = True

            # =================================================
            # Audit MEDIUM and CRITICAL
            # =================================================

            if policy["audit"]:

                write_audit({
                    "task_id":
                        task_id,

                    "destination":
                        destination,

                    "action":
                        action,

                    "risk":
                        risk,

                    "kem":
                        policy["kem"],

                    "sig":
                        policy["sig"],

                    "success":
                        True,

                    "timestamp":
                        time.time(),
                })

            return result

    finally:

        append_metric({

            "task_id":
                task_id,

            "source":
                "planner",

            "destination":
                destination,

            "action":
                action,

            "risk":
                risk,

            "security_mode":
                "adaptive_pqc",

            "kem_algorithm":
                policy["kem"],

            "signature_algorithm":
                policy["sig"]
                or "none",

            # =================================================
            # Crypto timing
            # =================================================

            "keygen_ms":
                round(
                    m.get(
                        "keygen_ms",
                        0,
                    ),
                    6,
                ),

            "encap_or_exchange_ms":
                round(
                    m.get(
                        "encap_ms",
                        0,
                    ),
                    6,
                ),

            "decap_or_exchange_ms":
                round(
                    m.get(
                        "decap_ms",
                        0,
                    ),
                    6,
                ),

            "sign_ms":
                round(
                    m.get(
                        "sign_ms",
                        0,
                    ),
                    6,
                ),

            "verify_ms":
                round(
                    m.get(
                        "verify_ms",
                        0,
                    ),
                    6,
                ),

            "encrypt_ms":
                round(
                    m.get(
                        "encrypt_ms",
                        0,
                    ),
                    6,
                ),

            "decrypt_ms":
                round(
                    m.get(
                        "decrypt_ms",
                        0,
                    ),
                    6,
                ),

            # =================================================
            # NEW crypto-object-size measurements
            # =================================================

            "public_key_bytes":
                m.get(
                    "public_key_bytes",
                    0,
                ),

            "kem_ciphertext_bytes":
                m.get(
                    "kem_ciphertext_bytes",
                    0,
                ),

            "signature_bytes":
                m.get(
                    "signature_bytes",
                    0,
                ),

            "encrypted_payload_bytes":
                m.get(
                    "encrypted_payload_bytes",
                    0,
                ),

            # =================================================
            # Agent/network metrics
            # =================================================

            "request_latency_ms":
                round(
                    m.get(
                        "request_ms",
                        0,
                    ),
                    4,
                ),

            "total_call_latency_ms":
                round(
                    (
                        time.perf_counter()
                        - total_start
                    )
                    * 1000,
                    4,
                ),

            "bytes_sent":
                m.get(
                    "request_bytes",
                    0,
                ),

            "bytes_received":
                response_bytes,

            "delegation_bytes":
                delegation_bytes,

            "audit_enabled":
                policy["audit"],

            "cpu_percent":
                psutil.cpu_percent(
                    interval=None
                ),

            "memory_mb":
                round(
                    process_memory_mb(),
                    3,
                ),

            "success":
                success,
        })


@app.post("/task")
async def task(t: TravelTask):

    task_id = str(
        uuid.uuid4()
    )

    # =========================================================
    # LOW
    # ML-KEM-512, no ML-DSA
    # =========================================================

    flights = await call_agent(
        task_id,
        "flight",
        "search_flight",
        "/search",
        {
            "origin":
                t.origin,

            "destination":
                t.destination,

            "date":
                t.date,
        },
    )

    valid = [
        f for f in flights["flights"]
        if f["price"] <= t.max_price
    ]

    if not valid:

        return {
            "task_id":
                task_id,

            "status":
                "not_booked",
        }

    selected = min(
        valid,
        key=lambda x: x["price"],
    )

    # =========================================================
    # MEDIUM
    # ML-KEM-768 + ML-DSA-65
    # =========================================================

    cal = await call_agent(
        task_id,
        "calendar",
        "check_calendar",
        "/check",
        {
            "date":
                t.date
        },
    )

    if not cal["available"]:

        return {
            "task_id":
                task_id,

            "status":
                "not_booked",

            "reason":
                "calendar",
        }

    if not t.auto_book:

        return {
            "task_id":
                task_id,

            "status":
                "ready_to_book",

            "flight":
                selected,
        }

    # =========================================================
    # CRITICAL
    # ML-KEM-1024 + ML-DSA-87 + delegation + audit
    # =========================================================

    pay = await call_agent(
        task_id,
        "payment",
        "payment",
        "/pay",
        {
            "amount":
                selected["price"],

            "flight_id":
                selected["flight_id"],
        },
    )

    return {
        "task_id":
            task_id,

        "status":
            "booked",

        "flight":
            selected,

        "calendar":
            cal,

        "payment":
            pay,
    }