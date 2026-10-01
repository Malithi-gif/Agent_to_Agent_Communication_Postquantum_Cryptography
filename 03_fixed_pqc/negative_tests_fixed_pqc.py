import asyncio
import base64
import csv
import json
import time
from pathlib import Path

import httpx

from config import AGENTS
from security.pqc import (
    seal_for_target,
    b64d,
)


# ============================================================
# Fixed PQC configuration
# ============================================================

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"

REPETITIONS = 50

OUTPUT_FILE = Path(
    "metrics/security_negative_tests_fixed_pqc.csv"
)

PAYMENT_URL = AGENTS["payment"]["url"]


# ============================================================
# Helper: find a field in the secure envelope
# ============================================================

def find_field(envelope, candidates):

    for name in candidates:

        if name in envelope:
            return name

    return None


# ============================================================
# Helper: modify one byte of Base64-encoded data
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
# Create a valid Fixed-PQC request
#
# ML-KEM-768
# ML-DSA-65
# AES-256-GCM
# ============================================================

async def create_valid_envelope(client):

    # --------------------------------------------------------
    # Get Payment Agent ML-KEM-768 public key
    # --------------------------------------------------------

    response = await client.get(
        PAYMENT_URL + "/crypto/public",
        params={
            "kem": KEM_ALG
        },
    )

    response.raise_for_status()

    key_info = response.json()

    public_key = b64d(
        key_info["public_key"]
    )

    # --------------------------------------------------------
    # Payment payload
    # --------------------------------------------------------

    payload = {
        "amount": 425.0,
        "flight_id": "AA123",
    }

    # --------------------------------------------------------
    # Protect request using Fixed PQC
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
# Send secure request
# ============================================================

async def send_request(
    client,
    envelope,
):

    start = time.perf_counter()

    try:

        response = await client.post(
            PAYMENT_URL + "/pay",
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
                "raw": response.text
            }

        # -----------------------------------------------------
        # Request is accepted only if payment is approved
        # -----------------------------------------------------

        accepted = (
            200 <= response.status_code < 300
            and body.get("status") == "approved"
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
# N1: Valid Fixed PQC request
# Expected: ACCEPT
# ============================================================

async def test_valid_request(client):

    envelope = await create_valid_envelope(
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

async def test_tampered_ciphertext(client):

    # --------------------------------------------------------
    # Generate a valid request first
    # --------------------------------------------------------

    envelope = await create_valid_envelope(
        client
    )

    # --------------------------------------------------------
    # Find ciphertext field
    # --------------------------------------------------------

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
            f"Envelope keys: {list(envelope.keys())}"
        )

    # --------------------------------------------------------
    # Modify ciphertext AFTER encryption.
    #
    # AES-GCM authentication should detect the change.
    # --------------------------------------------------------

    envelope[field] = tamper_base64_value(
        envelope[field]
    )

    return await send_request(
        client,
        envelope,
    )


# ============================================================
# N3: Invalid ML-DSA-65 signature
# Expected: REJECT
# ============================================================

async def test_invalid_signature(client):

    # --------------------------------------------------------
    # Generate a valid signed request
    # --------------------------------------------------------

    envelope = await create_valid_envelope(
        client
    )

    # --------------------------------------------------------
    # Find ML-DSA signature field
    # --------------------------------------------------------

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
            f"Envelope keys: {list(envelope.keys())}"
        )

    # --------------------------------------------------------
    # Modify signature AFTER signing.
    #
    # ML-DSA-65 verification should fail.
    # --------------------------------------------------------

    envelope[field] = tamper_base64_value(
        envelope[field]
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
            "N3_invalid_ml_dsa_65_signature",

        "attack":
            "ML-DSA-65 signature tampering",

        "expected":
            "reject",

        "function":
            test_invalid_signature,
    },
]


# ============================================================
# Main experiment
# ============================================================

async def main():

    print("=" * 70)

    print(
        "FIXED PQC NEGATIVE SECURITY TESTS"
    )

    print(
        "ML-KEM-768 + ML-DSA-65 + AES-256-GCM"
    )

    print("=" * 70)

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
                        == test["expected"]
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

                        "expected_result":
                            test["expected"],

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

                        "expected_result":
                            test["expected"],

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
            # Display result for current test
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
    # Save detailed results
    # ========================================================

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [

        "test_name",
        "run",
        "attack_type",
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

    print("\n" + "=" * 70)

    print(
        "FIXED PQC SECURITY TEST SUMMARY"
    )

    print("=" * 70)

    for test in TESTS:

        test_rows = [

            r for r in rows

            if r["test_name"]
            == test["name"]

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
    # N1 is valid and is excluded.
    # N2 and N3 are attack cases.
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
        "\nFixed PQC attack "
        "rejection rate: "
        f"{rejection_rate:.2f}%"
    )

    print(
        f"\nResults saved to: "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    asyncio.run(main())