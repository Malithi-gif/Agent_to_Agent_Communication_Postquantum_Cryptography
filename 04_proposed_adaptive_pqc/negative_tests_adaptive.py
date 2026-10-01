import asyncio
import base64
import csv
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import oqs

from config import AGENTS
from security.pqc import (
    seal_for_target,
    b64d,
    b64e,
    load_sig_secret,
)


# ============================================================
# Adaptive PQC configuration for CRITICAL payment
# ============================================================

KEM_ALG = "ML-KEM-1024"
SIG_ALG = "ML-DSA-87"

REPETITIONS = 50

OUTPUT_FILE = Path(
    "metrics/security_negative_tests_adaptive.csv"
)

PAYMENT_URL = AGENTS["payment"]["url"]


# ============================================================
# Helper: find field in secure envelope
# ============================================================

def find_field(envelope, candidates):

    for name in candidates:
        if name in envelope:
            return name

    return None


# ============================================================
# Helper: tamper Base64 value
# ============================================================

def tamper_base64_value(value):

    raw = bytearray(
        base64.b64decode(value)
    )

    if len(raw) == 0:
        return value

    # Flip one bit
    raw[0] ^= 0x01

    return base64.b64encode(
        bytes(raw)
    ).decode()


# ============================================================
# Create signed delegation token
# ============================================================

def make_delegation(
    task_id,
    destination="payment",
    action="payment",
    max_amount=500.0,
    expired=False,
):

    # --------------------------------------------------------
    # Valid token:
    # expires 5 minutes in future
    #
    # Expired token:
    # expired 5 minutes ago
    # --------------------------------------------------------

    if expired:

        expires_at = (
            datetime.now(timezone.utc)
            - timedelta(minutes=5)
        )

    else:

        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(minutes=5)
        )

    claims = {

        "task_id":
            task_id,

        "destination":
            destination,

        "action":
            action,

        "max_amount":
            max_amount,

        "expires_at":
            expires_at.isoformat(),

        "nonce":
            uuid.uuid4().hex,
    }

    # --------------------------------------------------------
    # Canonical representation of claims
    # --------------------------------------------------------

    body = json.dumps(
        claims,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    # --------------------------------------------------------
    # Sign delegation with ML-DSA-87
    # --------------------------------------------------------

    with oqs.Signature(
        "ML-DSA-87",
        load_sig_secret("ML-DSA-87"),
    ) as signer:

        signature = signer.sign(
            body
        )

    return {

        "claims":
            claims,

        "sig_alg":
            "ML-DSA-87",

        "signature":
            b64e(signature),
    }


# ============================================================
# Create valid Adaptive PQC envelope
#
# Payment is CRITICAL:
#
# ML-KEM-1024
# ML-DSA-87
# Delegation token
# AES-256-GCM
# ============================================================

async def create_envelope(
    client,
    amount=425.0,
    include_delegation=True,
    expired=False,
    delegation_action="payment",
    delegation_destination="payment",
    max_amount=500.0,
):

    task_id = str(
        uuid.uuid4()
    )

    payload = {

        "amount":
            amount,

        "flight_id":
            "AA123",
    }

    # --------------------------------------------------------
    # Add delegation token
    # --------------------------------------------------------

    if include_delegation:

        payload[
            "delegation_token"
        ] = make_delegation(

            task_id=task_id,

            destination=
                delegation_destination,

            action=
                delegation_action,

            max_amount=
                max_amount,

            expired=
                expired,
        )

    # --------------------------------------------------------
    # Obtain Payment Agent ML-KEM-1024 public key
    # --------------------------------------------------------

    response = await client.get(

        PAYMENT_URL
        + "/crypto/public",

        params={
            "kem":
                KEM_ALG
        },
    )

    response.raise_for_status()

    key_info = response.json()

    public_key = b64d(
        key_info["public_key"]
    )

    # --------------------------------------------------------
    # Protect request
    # --------------------------------------------------------

    envelope, _ = seal_for_target(

        "payment",

        payload,

        public_key,

        KEM_ALG,

        SIG_ALG,
    )

    return envelope


# ============================================================
# Send request
# ============================================================

async def send_request(
    client,
    envelope,
):

    start = time.perf_counter()

    try:

        response = await client.post(

            PAYMENT_URL
            + "/pay",

            json=envelope,
        )

        latency_ms = (
            time.perf_counter()
            - start
        ) * 1000

        try:

            body = response.json()

        except Exception:

            body = {
                "raw":
                    response.text
            }

        # -----------------------------------------------------
        # Valid payment should return approved
        # -----------------------------------------------------

        accepted = (

            200 <=
            response.status_code
            < 300

            and

            body.get("status")
            == "approved"
        )

        return {

            "accepted":
                accepted,

            "http_status":
                response.status_code,

            "latency_ms":
                latency_ms,

            "response":
                body,
        }

    except Exception as e:

        latency_ms = (
            time.perf_counter()
            - start
        ) * 1000

        return {

            "accepted":
                False,

            "http_status":
                0,

            "latency_ms":
                latency_ms,

            "response": {

                "error":
                    str(e)
            },
        }


# ============================================================
# N1: Valid request
# Expected: ACCEPT
# ============================================================

async def test_valid_request(client):

    envelope = await create_envelope(
        client
    )

    return await send_request(
        client,
        envelope,
    )


# ============================================================
# N2: Tampered AES-GCM ciphertext
# Expected: REJECT
# ============================================================

async def test_tampered_ciphertext(
    client
):

    envelope = await create_envelope(
        client
    )

    field = find_field(

        envelope,

        [
            "ciphertext",
            "encrypted_payload",
            "payload_ciphertext",
            "ct",
        ],
    )

    if field is None:

        raise RuntimeError(

            "Could not find ciphertext field. "
            f"Envelope keys: "
            f"{list(envelope.keys())}"
        )

    # --------------------------------------------------------
    # Modify ciphertext after encryption
    # --------------------------------------------------------

    envelope[field] = (
        tamper_base64_value(
            envelope[field]
        )
    )

    return await send_request(
        client,
        envelope,
    )


# ============================================================
# N3: Invalid ML-DSA-87 signature
# Expected: REJECT
# ============================================================

async def test_invalid_signature(
    client
):

    envelope = await create_envelope(
        client
    )

    field = find_field(

        envelope,

        [
            "signature",
            "sig",
            "ml_dsa_signature",
        ],
    )

    if field is None:

        raise RuntimeError(

            "Could not find signature field. "
            f"Envelope keys: "
            f"{list(envelope.keys())}"
        )

    # --------------------------------------------------------
    # Modify signature after signing
    # --------------------------------------------------------

    envelope[field] = (
        tamper_base64_value(
            envelope[field]
        )
    )

    return await send_request(
        client,
        envelope,
    )


# ============================================================
# N4: Missing delegation
# Expected: REJECT
# ============================================================

async def test_missing_delegation(
    client
):

    envelope = await create_envelope(

        client,

        include_delegation=False,
    )

    return await send_request(
        client,
        envelope,
    )


# ============================================================
# N5: Expired delegation
# Expected: REJECT
# ============================================================

async def test_expired_delegation(
    client
):

    envelope = await create_envelope(

        client,

        expired=True,
    )

    return await send_request(
        client,
        envelope,
    )


# ============================================================
# N6: Wrong action
# Expected: REJECT
# ============================================================

async def test_wrong_action(
    client
):

    envelope = await create_envelope(

        client,

        delegation_action=
            "search_flight",
    )

    return await send_request(
        client,
        envelope,
    )


# ============================================================
# N7: Wrong destination
# Expected: REJECT
# ============================================================

async def test_wrong_destination(
    client
):

    envelope = await create_envelope(

        client,

        delegation_destination=
            "calendar",
    )

    return await send_request(
        client,
        envelope,
    )


# ============================================================
# N8: Exceeded delegated payment amount
#
# Delegation allows $400
# Actual payment requests $425
#
# Expected: REJECT
# ============================================================

async def test_exceeded_amount(
    client
):

    envelope = await create_envelope(

        client,

        amount=425.0,

        max_amount=400.0,
    )

    return await send_request(
        client,
        envelope,
    )


# ============================================================
# Test definitions
# ============================================================

TESTS = [

    {
        "name":
            "N1_valid_request",

        "attack":
            "none",

        "expected":
            "accept",

        "function":
            test_valid_request,
    },

    {
        "name":
            "N2_tampered_ciphertext",

        "attack":
            "AES-GCM ciphertext tampering",

        "expected":
            "reject",

        "function":
            test_tampered_ciphertext,
    },

    {
        "name":
            "N3_invalid_ml_dsa_87_signature",

        "attack":
            "ML-DSA-87 signature tampering",

        "expected":
            "reject",

        "function":
            test_invalid_signature,
    },

    {
        "name":
            "N4_missing_delegation",

        "attack":
            "Missing delegation token",

        "expected":
            "reject",

        "function":
            test_missing_delegation,
    },

    {
        "name":
            "N5_expired_delegation",

        "attack":
            "Expired delegation token",

        "expected":
            "reject",

        "function":
            test_expired_delegation,
    },

    {
        "name":
            "N6_wrong_action",

        "attack":
            "Wrong delegation action",

        "expected":
            "reject",

        "function":
            test_wrong_action,
    },

    {
        "name":
            "N7_wrong_destination",

        "attack":
            "Wrong delegation destination",

        "expected":
            "reject",

        "function":
            test_wrong_destination,
    },

    {
        "name":
            "N8_exceeded_delegated_amount",

        "attack":
            "Payment exceeds delegated amount",

        "expected":
            "reject",

        "function":
            test_exceeded_amount,
    },
]


# ============================================================
# Main experiment
# ============================================================

async def main():

    print("=" * 75)

    print(
        "PROPOSED ADAPTIVE PQC "
        "NEGATIVE SECURITY TESTS"
    )

    print(
        "CRITICAL payment: "
        "ML-KEM-1024 + ML-DSA-87 "
        "+ delegation + AES-256-GCM"
    )

    print("=" * 75)

    rows = []

    async with httpx.AsyncClient(
        timeout=60.0
    ) as client:

        for test in TESTS:

            print(

                f"\nRunning "
                f"{test['name']} "
                f"({REPETITIONS} repetitions)"
            )

            for run in range(
                1,
                REPETITIONS + 1
            ):

                try:

                    result = await (
                        test["function"](
                            client
                        )
                    )

                    actual = (

                        "accept"

                        if result[
                            "accepted"
                        ]

                        else "reject"
                    )

                    passed = (

                        actual
                        == test[
                            "expected"
                        ]
                    )

                    response_text = (
                        json.dumps(
                            result[
                                "response"
                            ],
                            separators=(
                                ",",
                                ":",
                            ),
                        )
                    )

                    rows.append({

                        "test_name":
                            test["name"],

                        "run":
                            run,

                        "attack_type":
                            test["attack"],

                        "risk":
                            "CRITICAL",

                        "expected_result":
                            test[
                                "expected"
                            ],

                        "actual_result":
                            actual,

                        "test_passed":
                            passed,

                        "http_status":
                            result[
                                "http_status"
                            ],

                        "rejected":
                            not result[
                                "accepted"
                            ],

                        "detection_latency_ms":
                            round(
                                result[
                                    "latency_ms"
                                ],
                                4,
                            ),

                        "reason":
                            response_text[
                                :500
                            ],
                    })

                except Exception as e:

                    rows.append({

                        "test_name":
                            test["name"],

                        "run":
                            run,

                        "attack_type":
                            test["attack"],

                        "risk":
                            "CRITICAL",

                        "expected_result":
                            test[
                                "expected"
                            ],

                        "actual_result":
                            "test_error",

                        "test_passed":
                            False,

                        "http_status":
                            0,

                        "rejected":
                            False,

                        "detection_latency_ms":
                            0,

                        "reason":
                            str(e),
                    })


            # ------------------------------------------------
            # Display current test result
            # ------------------------------------------------

            current_rows = [

                r for r in rows

                if r["test_name"]
                == test["name"]

            ]

            passed_count = sum(

                1 for r
                in current_rows

                if r[
                    "test_passed"
                ]
            )

            print(

                f"{test['name']}: "
                f"{passed_count}/"
                f"{REPETITIONS} passed"
            )


    # ========================================================
    # Save detailed CSV
    # ========================================================

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [

        "test_name",
        "run",
        "attack_type",
        "risk",
        "expected_result",
        "actual_result",
        "test_passed",
        "http_status",
        "rejected",
        "detection_latency_ms",
        "reason",

    ]

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(
            rows
        )


    # ========================================================
    # Summary
    # ========================================================

    print("\n" + "=" * 75)

    print(
        "ADAPTIVE PQC SECURITY TEST SUMMARY"
    )

    print("=" * 75)

    for test in TESTS:

        test_rows = [

            r for r in rows

            if r[
                "test_name"
            ] == test["name"]

        ]

        passed = sum(

            1 for r
            in test_rows

            if r[
                "test_passed"
            ]
        )

        print(

            f"{test['name']:<40} "
            f"{passed}/"
            f"{len(test_rows)} passed"
        )


    # ========================================================
    # Attack rejection rate
    #
    # N1 is valid and excluded.
    # N2-N8 are malicious/invalid requests.
    # ========================================================

    attack_rows = [

        r for r in rows

        if r[
            "expected_result"
        ] == "reject"

    ]

    rejected_attacks = sum(

        1 for r
        in attack_rows

        if r[
            "actual_result"
        ] == "reject"

    )

    rejection_rate = (

        rejected_attacks
        / len(attack_rows)
        * 100

        if attack_rows
        else 0
    )


    print(
        "\nAdaptive PQC attack "
        "rejection rate: "
        f"{rejection_rate:.2f}%"
    )

    print(
        f"\nResults saved to: "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    asyncio.run(main())