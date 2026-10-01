import json
import time
import uuid

import httpx
import psutil
from fastapi import FastAPI
from pydantic import BaseModel

from config import AGENTS, MAX_BOOKING_PRICE
from metrics.collector import append_metric, process_memory_mb
from security.risk import classify_risk
from security.pqc import seal_for_target, b64d


KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"


app = FastAPI(title="Fixed PQC Planner")


class TravelTask(BaseModel):
    origin: str = "ORD"
    destination: str = "JFK"
    date: str
    max_price: float = MAX_BOOKING_PRICE
    auto_book: bool = True


def decoded_size(value):
    """
    Return raw byte size of a Base64-encoded object.
    Returns 0 if value is missing or cannot be decoded.
    """

    if not value:
        return 0

    try:
        return len(b64d(value))
    except Exception:
        return 0


def find_decoded_size(envelope, possible_names):
    """
    Check several possible envelope field names.
    This makes the measurement tolerant to naming
    differences in security/pqc.py.
    """

    for name in possible_names:

        if name in envelope:

            size = decoded_size(
                envelope.get(name)
            )

            if size > 0:
                return size

    return 0


async def call_agent(
    task_id,
    destination,
    action,
    endpoint,
    payload,
):

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

        # NEW
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
            # Obtain ML-KEM-768 public key
            # =================================================

            kr = await client.get(
                AGENTS[destination]["url"]
                + "/crypto/public",

                params={
                    "kem": KEM_ALG
                },
            )

            kr.raise_for_status()

            ki = kr.json()

            target_public_key = b64d(
                ki["public_key"]
            )

            # Raw ML-KEM public-key size
            m["public_key_bytes"] = len(
                target_public_key
            )

            # =================================================
            # PQC protection
            # =================================================

            envelope, c = seal_for_target(
                action,
                payload,
                target_public_key,
                KEM_ALG,
                SIG_ALG,
            )

            # =================================================
            # NEW crypto-object-size measurements
            # =================================================

            # First use sizes returned directly by pqc.py
            # if they are available.

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

            # =================================================
            # Fallback: measure Base64 objects from envelope
            # =================================================

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

            # =================================================
            # Serialized transmitted message size
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

            # =================================================
            # Target-side crypto measurements
            # =================================================

            s = result.pop(
                "crypto_metrics",
                {},
            )

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
                classify_risk(action),

            "security_mode":
                "fixed_pqc",

            "kem_algorithm":
                KEM_ALG,

            "signature_algorithm":
                SIG_ALG,

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
            # NEW crypto-object sizes
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
            # Request/network metrics
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
                0,

            # Fixed-PQC baseline has no adaptive audit policy.
            "audit_enabled":
                False,

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
    # Flight — LOW risk
    # Fixed PQC still uses ML-KEM-768 + ML-DSA-65
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
    # Calendar — MEDIUM risk
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
    # Payment — CRITICAL risk
    # Fixed PQC still uses same suite
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