import csv
import statistics
from pathlib import Path
from collections import defaultdict


SYSTEMS = {
    "standard": Path(
        "01_standard_tls_bearer/metrics/results_standard_tls.csv"
    ),
    "classical": Path(
        "02_classical_crypto/metrics/results_classical.csv"
    ),
    "fixed_pqc": Path(
        "03_fixed_pqc/metrics/results_fixed_pqc.csv"
    ),
    "adaptive_pqc": Path(
        "04_proposed_adaptive_pqc/metrics/results_adaptive_pqc.csv"
    ),
}


OUTPUT_TASKS = Path(
    "communication_task_level.csv"
)

OUTPUT_SUMMARY = Path(
    "communication_summary.csv"
)


def percentile(values, p):
    if not values:
        return 0.0

    values = sorted(values)

    index = (len(values) - 1) * p / 100

    lower = int(index)

    upper = min(
        lower + 1,
        len(values) - 1
    )

    if lower == upper:
        return values[lower]

    fraction = index - lower

    return (
        values[lower] * (1 - fraction)
        + values[upper] * fraction
    )


def to_int(value):
    try:
        return int(float(value))
    except (ValueError, TypeError):
        return 0


def analyze_system(system_name, csv_path):

    print(
        f"\nAnalyzing {system_name}: "
        f"{csv_path}"
    )

    if not csv_path.exists():
        print(
            f"WARNING: file not found: "
            f"{csv_path}"
        )
        return [], None

    task_data = defaultdict(
        lambda: {
            "bytes_sent": 0,
            "bytes_received": 0,

            "public_key_bytes": 0,
            "kem_ciphertext_bytes": 0,
            "signature_bytes": 0,
            "encrypted_payload_bytes": 0,
            "delegation_bytes": 0,

            "agent_calls": 0,
        }
    )

    with csv_path.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:

            task_id = row.get(
                "task_id",
                ""
            )

            if not task_id:
                continue

            t = task_data[task_id]

            t["bytes_sent"] += to_int(
                row.get(
                    "bytes_sent",
                    0
                )
            )

            t["bytes_received"] += to_int(
                row.get(
                    "bytes_received",
                    0
                )
            )

            t["public_key_bytes"] += to_int(
                row.get(
                    "public_key_bytes",
                    0
                )
            )

            t["kem_ciphertext_bytes"] += to_int(
                row.get(
                    "kem_ciphertext_bytes",
                    0
                )
            )

            t["signature_bytes"] += to_int(
                row.get(
                    "signature_bytes",
                    0
                )
            )

            t["encrypted_payload_bytes"] += to_int(
                row.get(
                    "encrypted_payload_bytes",
                    0
                )
            )

            t["delegation_bytes"] += to_int(
                row.get(
                    "delegation_bytes",
                    0
                )
            )

            t["agent_calls"] += 1

    task_rows = []

    for task_id, values in task_data.items():

        total_network_bytes = (
            values["bytes_sent"]
            + values["bytes_received"]
        )

        total_crypto_bytes = (
            values["public_key_bytes"]
            + values["kem_ciphertext_bytes"]
            + values["signature_bytes"]
            + values["encrypted_payload_bytes"]
            + values["delegation_bytes"]
        )

        task_rows.append({
            "system":
                system_name,

            "task_id":
                task_id,

            "agent_calls":
                values["agent_calls"],

            "bytes_sent":
                values["bytes_sent"],

            "bytes_received":
                values["bytes_received"],

            "total_network_bytes":
                total_network_bytes,

            "public_key_bytes":
                values["public_key_bytes"],

            "kem_ciphertext_bytes":
                values["kem_ciphertext_bytes"],

            "signature_bytes":
                values["signature_bytes"],

            "encrypted_payload_bytes":
                values["encrypted_payload_bytes"],

            "delegation_bytes":
                values["delegation_bytes"],

            "total_crypto_bytes":
                total_crypto_bytes,
        })

    network_values = [
        r["total_network_bytes"]
        for r in task_rows
    ]

    crypto_values = [
        r["total_crypto_bytes"]
        for r in task_rows
    ]

    sent_values = [
        r["bytes_sent"]
        for r in task_rows
    ]

    received_values = [
        r["bytes_received"]
        for r in task_rows
    ]

    if not network_values:
        return task_rows, None

    summary = {
        "system":
            system_name,

        "tasks":
            len(task_rows),

        "mean_bytes_per_task":
            statistics.mean(
                network_values
            ),

        "median_bytes_per_task":
            statistics.median(
                network_values
            ),

        "std_bytes_per_task":
            statistics.stdev(
                network_values
            )
            if len(network_values) > 1
            else 0,

        "p95_bytes_per_task":
            percentile(
                network_values,
                95
            ),

        "p99_bytes_per_task":
            percentile(
                network_values,
                99
            ),

        "mean_bytes_sent":
            statistics.mean(
                sent_values
            ),

        "mean_bytes_received":
            statistics.mean(
                received_values
            ),

        "mean_crypto_bytes_per_task":
            statistics.mean(
                crypto_values
            ),

        "mean_public_key_bytes":
            statistics.mean(
                [
                    r["public_key_bytes"]
                    for r in task_rows
                ]
            ),

        "mean_kem_ciphertext_bytes":
            statistics.mean(
                [
                    r["kem_ciphertext_bytes"]
                    for r in task_rows
                ]
            ),

        "mean_signature_bytes":
            statistics.mean(
                [
                    r["signature_bytes"]
                    for r in task_rows
                ]
            ),

        "mean_encrypted_payload_bytes":
            statistics.mean(
                [
                    r["encrypted_payload_bytes"]
                    for r in task_rows
                ]
            ),

        "mean_delegation_bytes":
            statistics.mean(
                [
                    r["delegation_bytes"]
                    for r in task_rows
                ]
            ),
    }

    return task_rows, summary


def main():

    all_task_rows = []
    summaries = []

    for system_name, csv_path in SYSTEMS.items():

        rows, summary = analyze_system(
            system_name,
            csv_path,
        )

        all_task_rows.extend(
            rows
        )

        if summary:
            summaries.append(
                summary
            )

    # =========================================================
    # Save task-level communication results
    # =========================================================

    if all_task_rows:

        with OUTPUT_TASKS.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as f:

            fieldnames = [
                "system",
                "task_id",
                "agent_calls",

                "bytes_sent",
                "bytes_received",
                "total_network_bytes",

                "public_key_bytes",
                "kem_ciphertext_bytes",
                "signature_bytes",
                "encrypted_payload_bytes",
                "delegation_bytes",

                "total_crypto_bytes",
            ]

            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
            )

            writer.writeheader()

            writer.writerows(
                all_task_rows
            )

    # =========================================================
    # Save summary results
    # =========================================================

    if summaries:

        with OUTPUT_SUMMARY.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as f:

            fieldnames = [
                "system",
                "tasks",

                "mean_bytes_per_task",
                "median_bytes_per_task",
                "std_bytes_per_task",
                "p95_bytes_per_task",
                "p99_bytes_per_task",

                "mean_bytes_sent",
                "mean_bytes_received",

                "mean_crypto_bytes_per_task",

                "mean_public_key_bytes",
                "mean_kem_ciphertext_bytes",
                "mean_signature_bytes",
                "mean_encrypted_payload_bytes",
                "mean_delegation_bytes",
            ]

            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
            )

            writer.writeheader()

            writer.writerows(
                summaries
            )

    print("\n" + "=" * 70)
    print("WORKFLOW COMMUNICATION SUMMARY")
    print("=" * 70)

    for s in summaries:

        print(
            f"\n{s['system']}"
        )

        print(
            f"Tasks               : "
            f"{s['tasks']}"
        )

        print(
            f"Mean bytes/task     : "
            f"{s['mean_bytes_per_task']:.2f}"
        )

        print(
            f"Median bytes/task   : "
            f"{s['median_bytes_per_task']:.2f}"
        )

        print(
            f"P95 bytes/task      : "
            f"{s['p95_bytes_per_task']:.2f}"
        )

        print(
            f"Mean crypto bytes   : "
            f"{s['mean_crypto_bytes_per_task']:.2f}"
        )

    print(
        f"\nTask-level output: "
        f"{OUTPUT_TASKS}"
    )

    print(
        f"Summary output: "
        f"{OUTPUT_SUMMARY}"
    )


if __name__ == "__main__":
    main()