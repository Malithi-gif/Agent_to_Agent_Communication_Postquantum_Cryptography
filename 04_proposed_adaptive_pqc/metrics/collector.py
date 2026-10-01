RESULT_FILENAME = "results_adaptive_pqc.csv"

import csv
import os
import time
from pathlib import Path

import psutil


RESULT_FILE = Path(__file__).resolve().parent / RESULT_FILENAME


FIELDS = [
    "timestamp",
    "task_id",
    "source",
    "destination",
    "action",
    "risk",

    "security_mode",
    "kem_algorithm",
    "signature_algorithm",

    "keygen_ms",
    "encap_or_exchange_ms",
    "decap_or_exchange_ms",
    "sign_ms",
    "verify_ms",
    "encrypt_ms",
    "decrypt_ms",

    # NEW crypto-object-size fields
    "public_key_bytes",
    "kem_ciphertext_bytes",
    "signature_bytes",
    "encrypted_payload_bytes",

    "request_latency_ms",
    "total_call_latency_ms",

    "bytes_sent",
    "bytes_received",

    "delegation_bytes",
    "audit_enabled",

    "cpu_percent",
    "memory_mb",
    "success",
]


def process_memory_mb():
    return (
        psutil.Process(os.getpid())
        .memory_info()
        .rss
        / (1024 * 1024)
    )


def append_metric(row: dict):
    RESULT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    exists = RESULT_FILE.exists()

    completed = {
        k: row.get(k, "")
        for k in FIELDS
    }

    completed["timestamp"] = time.time()

    with RESULT_FILE.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=FIELDS,
        )

        if not exists:
            writer.writeheader()

        writer.writerow(completed)