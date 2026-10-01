import asyncio
import csv
import statistics
import time
from pathlib import Path

import httpx

from config import AGENTS
from metrics.collector import RESULT_FILE


WARMUP_TASKS = 20
MEASURED_TASKS = 500

TASK_RESULTS = Path("metrics/task_level_fixed_pqc.csv")
SUMMARY_RESULTS = Path("metrics/summary_fixed_pqc.csv")


def percentile(values, p):
    if not values:
        return 0.0

    values = sorted(values)

    index = (len(values) - 1) * p / 100
    lower = int(index)
    upper = min(lower + 1, len(values) - 1)

    if lower == upper:
        return values[lower]

    fraction = index - lower

    return (
        values[lower] * (1 - fraction)
        + values[upper] * fraction
    )


async def send_task(client, task_number):

    task = {
        "origin": "ORD",
        "destination": "JFK",
        "date": "2026-08-14",
        "max_price": 500,
        "auto_book": True,
    }

    start = time.perf_counter()

    try:
        response = await client.post(
            AGENTS["planner"]["url"] + "/task",
            json=task,
        )

        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        response.raise_for_status()

        data = response.json()

        success = (
            data.get("status") == "booked"
        )

        return {
            "task_number": task_number,
            "task_id": data.get("task_id", ""),
            "latency_ms": round(latency_ms, 4),
            "success": success,
            "http_status": response.status_code,
            "error": "",
        }

    except Exception as e:

        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        return {
            "task_number": task_number,
            "task_id": "",
            "latency_ms": round(latency_ms, 4),
            "success": False,
            "http_status": 0,
            "error": str(e),
        }


async def main():

    print("=" * 60)
    print("FIXED PQC BENCHMARK")
    print("ML-KEM-768 + ML-DSA-65 + AES-256-GCM")
    print("=" * 60)

    async with httpx.AsyncClient(
        timeout=60.0
    ) as client:

        # =============================================
        # WARM-UP
        # =============================================

        print(
            f"\nRunning {WARMUP_TASKS} warm-up tasks..."
        )

        for i in range(WARMUP_TASKS):

            result = await send_task(
                client,
                i + 1,
            )

            print(
                f"Warm-up {i + 1}/{WARMUP_TASKS}: "
                f"{result['latency_ms']:.2f} ms"
            )

        print("\nWarm-up completed.")

        # =============================================
        # DELETE WARM-UP AGENT METRICS
        # =============================================

        if RESULT_FILE.exists():

            RESULT_FILE.unlink()

            print(
                f"Deleted warm-up metrics: "
                f"{RESULT_FILE}"
            )

        # =============================================
        # MEASURED EXPERIMENT
        # =============================================

        print(
            f"\nRunning {MEASURED_TASKS} measured tasks..."
        )

        results = []

        experiment_start = time.perf_counter()

        for i in range(MEASURED_TASKS):

            result = await send_task(
                client,
                i + 1,
            )

            results.append(result)

            if (i + 1) % 25 == 0:

                print(
                    f"Completed "
                    f"{i + 1}/{MEASURED_TASKS}"
                )

        experiment_seconds = (
            time.perf_counter()
            - experiment_start
        )

    # =============================================
    # SAVE TASK-LEVEL RESULTS
    # =============================================

    TASK_RESULTS.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with TASK_RESULTS.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        fieldnames = [
            "task_number",
            "task_id",
            "latency_ms",
            "success",
            "http_status",
            "error",
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for result in results:

            writer.writerow({
                "task_number":
                    result.get("task_number"),

                "task_id":
                    result.get("task_id", ""),

                "latency_ms":
                    result.get("latency_ms"),

                "success":
                    result.get("success"),

                "http_status":
                    result.get("http_status"),

                "error":
                    result.get("error", ""),
            })

    # =============================================
    # STATISTICS
    # =============================================

    successful = [
        r for r in results
        if r["success"]
    ]

    latencies = [
        r["latency_ms"]
        for r in successful
    ]

    success_count = len(successful)

    failed_count = (
        MEASURED_TASKS - success_count
    )

    completion_rate = (
        success_count
        / MEASURED_TASKS
        * 100
    )

    throughput = (
        success_count
        / experiment_seconds
        if experiment_seconds > 0
        else 0
    )

    mean_latency = (
        statistics.mean(latencies)
        if latencies
        else 0.0
    )

    median_latency = (
        statistics.median(latencies)
        if latencies
        else 0.0
    )

    std_latency = (
        statistics.stdev(latencies)
        if len(latencies) > 1
        else 0.0
    )

    p95_latency = percentile(
        latencies,
        95
    )

    p99_latency = percentile(
        latencies,
        99
    )

    # =============================================
    # PRINT RESULTS
    # =============================================

    print("\n")
    print("=" * 60)
    print("FIXED PQC RESULTS")
    print("=" * 60)

    print(
        f"Measured tasks      : "
        f"{MEASURED_TASKS}"
    )

    print(
        f"Successful tasks    : "
        f"{success_count}"
    )

    print(
        f"Failed tasks        : "
        f"{failed_count}"
    )

    print(
        f"Completion rate     : "
        f"{completion_rate:.2f}%"
    )

    print(
        f"Mean latency        : "
        f"{mean_latency:.4f} ms"
    )

    print(
        f"Median latency      : "
        f"{median_latency:.4f} ms"
    )

    print(
        f"Std deviation       : "
        f"{std_latency:.4f} ms"
    )

    print(
        f"P95 latency         : "
        f"{p95_latency:.4f} ms"
    )

    print(
        f"P99 latency         : "
        f"{p99_latency:.4f} ms"
    )

    print(
        f"Throughput          : "
        f"{throughput:.4f} tasks/sec"
    )

    print(
        f"Experiment duration : "
        f"{experiment_seconds:.2f} sec"
    )

    # =============================================
    # SAVE SUMMARY CSV
    # =============================================

    with SUMMARY_RESULTS.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        fieldnames = [
            "security_mode",
            "kem_algorithm",
            "signature_algorithm",
            "warmup_tasks",
            "measured_tasks",
            "successful_tasks",
            "failed_tasks",
            "completion_rate_percent",
            "mean_latency_ms",
            "median_latency_ms",
            "std_deviation_ms",
            "p95_latency_ms",
            "p99_latency_ms",
            "throughput_tasks_per_sec",
            "experiment_duration_sec",
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerow({
            "security_mode": "fixed_pqc",
            "kem_algorithm": "ML-KEM-768",
            "signature_algorithm": "ML-DSA-65",
            "warmup_tasks": WARMUP_TASKS,
            "measured_tasks": MEASURED_TASKS,
            "successful_tasks": success_count,
            "failed_tasks": failed_count,
            "completion_rate_percent":
                round(completion_rate, 4),
            "mean_latency_ms":
                round(mean_latency, 4),
            "median_latency_ms":
                round(median_latency, 4),
            "std_deviation_ms":
                round(std_latency, 4),
            "p95_latency_ms":
                round(p95_latency, 4),
            "p99_latency_ms":
                round(p99_latency, 4),
            "throughput_tasks_per_sec":
                round(throughput, 4),
            "experiment_duration_sec":
                round(experiment_seconds, 4),
        })

    print("\nTask-level results:")
    print(TASK_RESULTS)

    print("\nAgent-level results:")
    print(RESULT_FILE)

    print("\nSummary results:")
    print(SUMMARY_RESULTS)


if __name__ == "__main__":
    asyncio.run(main())