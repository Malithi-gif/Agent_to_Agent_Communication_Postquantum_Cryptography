import asyncio
import csv
import statistics
import time
from pathlib import Path

import httpx

from config import AGENTS


CONCURRENCY_LEVELS = [2, 5, 10, 20, 50]

# Number of complete workflows executed at each concurrency level
TASKS_PER_LEVEL = 100

OUTPUT_FILE = Path("metrics/scalability_adaptive_pqc.csv")


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


async def send_one_task(client, task_number):

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
            "latency_ms": latency_ms,
            "success": success,
            "status": response.status_code,
            "error": "",
        }

    except Exception as e:

        latency_ms = (
            time.perf_counter() - start
        ) * 1000

        return {
            "task_number": task_number,
            "latency_ms": latency_ms,
            "success": False,
            "status": 0,
            "error": str(e),
        }


async def run_concurrency_level(concurrency):

    print("\n" + "=" * 60)
    print(
        f"PROPOSED ADAPTIVE PQC SCALABILITY "
        f"- CONCURRENCY {concurrency}"
    )

    print(
        "LOW: ML-KEM-512 | "
        "MEDIUM: ML-KEM-768 + ML-DSA-65 | "
        "CRITICAL: ML-KEM-1024 + ML-DSA-87 + Delegation"
    )

    print("=" * 60)

    semaphore = asyncio.Semaphore(
        concurrency
    )

    async with httpx.AsyncClient(
        timeout=120.0,
        limits=httpx.Limits(
            max_connections=100,
            max_keepalive_connections=100,
        ),
    ) as client:

        async def limited_task(i):

            async with semaphore:
                return await send_one_task(
                    client,
                    i,
                )

        tasks = [
            limited_task(i + 1)
            for i in range(
                TASKS_PER_LEVEL
            )
        ]

        start = time.perf_counter()

        results = await asyncio.gather(
            *tasks
        )

        duration = (
            time.perf_counter()
            - start
        )

    successful = [
        r for r in results
        if r["success"]
    ]

    latencies = [
        r["latency_ms"]
        for r in successful
    ]

    success_count = len(
        successful
    )

    failed_count = (
        TASKS_PER_LEVEL
        - success_count
    )

    completion_rate = (
        success_count
        / TASKS_PER_LEVEL
        * 100
    )

    throughput = (
        success_count
        / duration
        if duration > 0
        else 0
    )

    mean_latency = (
        statistics.mean(latencies)
        if latencies
        else 0
    )

    median_latency = (
        statistics.median(latencies)
        if latencies
        else 0
    )

    std_latency = (
        statistics.stdev(latencies)
        if len(latencies) > 1
        else 0
    )

    p95 = percentile(
        latencies,
        95
    )

    p99 = percentile(
        latencies,
        99
    )

    print(
        f"Tasks              : "
        f"{TASKS_PER_LEVEL}"
    )

    print(
        f"Successful         : "
        f"{success_count}"
    )

    print(
        f"Failed             : "
        f"{failed_count}"
    )

    print(
        f"Completion rate    : "
        f"{completion_rate:.2f}%"
    )

    print(
        f"Mean latency       : "
        f"{mean_latency:.4f} ms"
    )

    print(
        f"Median latency     : "
        f"{median_latency:.4f} ms"
    )

    print(
        f"Std deviation      : "
        f"{std_latency:.4f} ms"
    )

    print(
        f"P95 latency        : "
        f"{p95:.4f} ms"
    )

    print(
        f"P99 latency        : "
        f"{p99:.4f} ms"
    )

    print(
        f"Throughput         : "
        f"{throughput:.4f} tasks/sec"
    )

    print(
        f"Duration           : "
        f"{duration:.2f} sec"
    )

    return {
        "system":
            "adaptive_pqc",

        "security":
            (
                "LOW=ML-KEM-512; "
                "MEDIUM=ML-KEM-768+ML-DSA-65; "
                "CRITICAL=ML-KEM-1024+ML-DSA-87+Delegation+Audit"
            ),

        "concurrency":
            concurrency,

        "tasks":
            TASKS_PER_LEVEL,

        "successful_tasks":
            success_count,

        "failed_tasks":
            failed_count,

        "completion_rate_percent":
            round(
                completion_rate,
                4
            ),

        "mean_latency_ms":
            round(
                mean_latency,
                4
            ),

        "median_latency_ms":
            round(
                median_latency,
                4
            ),

        "std_deviation_ms":
            round(
                std_latency,
                4
            ),

        "p95_latency_ms":
            round(
                p95,
                4
            ),

        "p99_latency_ms":
            round(
                p99,
                4
            ),

        "throughput_tasks_per_sec":
            round(
                throughput,
                4
            ),

        "experiment_duration_sec":
            round(
                duration,
                4
            ),
    }


async def main():

    print("=" * 60)
    print(
        "PROPOSED ADAPTIVE PQC "
        "SCALABILITY EXPERIMENT"
    )

    print(
        "Risk-adaptive ML-KEM / ML-DSA "
        "+ Delegation + Audit"
    )

    print("=" * 60)

    results = []

    for concurrency in (
        CONCURRENCY_LEVELS
    ):

        result = (
            await run_concurrency_level(
                concurrency
            )
        )

        results.append(
            result
        )

        # Short pause between levels
        await asyncio.sleep(2)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        fieldnames = [
            "system",
            "security",
            "concurrency",
            "tasks",
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

        writer.writerows(
            results
        )

    print("\n" + "=" * 60)
    print(
        "ADAPTIVE PQC SCALABILITY "
        "EXPERIMENT COMPLETE"
    )
    print("=" * 60)

    print(
        f"Results saved to: "
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    asyncio.run(main())