import asyncio
import csv
import json
import time
from pathlib import Path

import httpx

from config import ACCESS_TOKEN, AGENTS, CERT_FILE


REPETITIONS = 50

OUTPUT_FILE = Path(
    "metrics/security_negative_tests_standard.csv"
)


TASK = {
    "origin": "ORD",
    "destination": "JFK",
    "date": "2026-08-14",
    "max_price": 500,
    "auto_book": True,
}


# ============================================================
# Send request
# ============================================================

async def send_request(client, headers=None):

    start = time.perf_counter()

    try:

        response = await client.post(
            AGENTS["planner"]["url"] + "/task",
            json=TASK,
            headers=headers,
        )

        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        try:
            body = response.json()

        except Exception:
            body = {
                "raw": response.text
            }

        # -----------------------------------------------------
        # A request is considered accepted only if the complete
        # travel workflow successfully books the flight.
        # -----------------------------------------------------

        accepted = (
            response.status_code == 200
            and body.get("status") == "booked"
        )

        return {
            "accepted": accepted,
            "http_status": response.status_code,
            "latency_ms": latency_ms,
            "response": body,
        }

    except Exception as e:

        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        return {
            "accepted": False,
            "http_status": 0,
            "latency_ms": latency_ms,
            "response": {
                "error": str(e)
            },
        }


# ============================================================
# N1: Valid bearer token
# Expected: ACCEPT
# ============================================================

async def test_valid_token(client):

    headers = {
        "Authorization":
            f"Bearer {ACCESS_TOKEN}"
    }

    return await send_request(
        client,
        headers,
    )


# ============================================================
# N2: Missing bearer token
# Expected: REJECT
# ============================================================

async def test_missing_token(client):

    return await send_request(
        client,
        headers=None,
    )


# ============================================================
# N3: Invalid bearer token
# Expected: REJECT
# ============================================================

async def test_invalid_token(client):

    headers = {
        "Authorization":
            "Bearer invalid-token-12345"
    }

    return await send_request(
        client,
        headers,
    )


# ============================================================
# N4: Malformed Authorization header
# Expected: REJECT
# ============================================================

async def test_malformed_token(client):

    headers = {
        "Authorization":
            ACCESS_TOKEN
    }

    # Missing "Bearer " prefix

    return await send_request(
        client,
        headers,
    )


# ============================================================
# Test definitions
# ============================================================

TESTS = [

    {
        "name":
            "N1_valid_token",

        "attack":
            "none",

        "expected":
            "accept",

        "function":
            test_valid_token,
    },

    {
        "name":
            "N2_missing_token",

        "attack":
            "Bearer token removed",

        "expected":
            "reject",

        "function":
            test_missing_token,
    },

    {
        "name":
            "N3_invalid_token",

        "attack":
            "Invalid bearer token",

        "expected":
            "reject",

        "function":
            test_invalid_token,
    },

    {
        "name":
            "N4_malformed_token",

        "attack":
            "Malformed Authorization header",

        "expected":
            "reject",

        "function":
            test_malformed_token,
    },
]


# ============================================================
# Main experiment
# ============================================================

async def main():

    print("=" * 70)

    print(
        "STANDARD TLS + BEARER "
        "NEGATIVE SECURITY TESTS"
    )

    print("=" * 70)

    rows = []

    # --------------------------------------------------------
    # Important:
    # Certificate verification remains enabled.
    # We do NOT use verify=False.
    # --------------------------------------------------------

    async with httpx.AsyncClient(
        timeout=60.0,
        verify=str(CERT_FILE),
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
            # Display result for this test
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
        "STANDARD SECURITY TEST SUMMARY"
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

            f"{test['name']:<30} "
            f"{passed}/"
            f"{len(test_rows)} passed"

        )

    # ========================================================
    # Authentication attack rejection rate
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
        "\nAuthentication attack "
        "rejection rate: "
        f"{rejection_rate:.2f}%"
    )

    print(
        f"\nResults saved to: "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    asyncio.run(main())