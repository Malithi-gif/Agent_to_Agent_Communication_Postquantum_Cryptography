import subprocess
import sys
import time
from pathlib import Path

from config import CERT_FILE, KEY_FILE

ROOT = Path(__file__).resolve().parent

SERVERS = [
    ("planner", "agents.planner_agent:app", 8001),
    ("flight", "agents.flight_agent:app", 8002),
    ("calendar", "agents.calendar_agent:app", 8013),
    ("payment", "agents.payment_agent:app", 8004),
]


def main():
    processes = []

    try:
        print("Preparing local TLS certificate...")
        subprocess.run(
            [sys.executable, str(ROOT / "setup_tls.py")],
            cwd=str(ROOT),
            check=True,
        )

        for name, app, port in SERVERS:
            print(f"Starting {name} on https://127.0.0.1:{port}")

            p = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    app,
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--ssl-keyfile",
                    str(KEY_FILE),
                    "--ssl-certfile",
                    str(CERT_FILE),
                ],
                cwd=str(ROOT),
            )

            processes.append(p)

        print("\nAll TLS-enabled agents started.")
        print("Press Ctrl+C to stop.\n")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping agents...")

    finally:
        for p in processes:
            p.terminate()

        for p in processes:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    main()
