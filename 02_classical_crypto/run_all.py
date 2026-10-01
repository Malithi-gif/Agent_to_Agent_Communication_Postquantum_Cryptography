import subprocess
import sys
import time
from pathlib import Path

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
        setup = ROOT / "setup_keys.py"
        if setup.exists():
            print("Preparing cryptographic identity keys...")
            subprocess.run([sys.executable, str(setup)], cwd=str(ROOT), check=True)

        for name, app, port in SERVERS:
            print(f"Starting {name} on http://127.0.0.1:{port}")
            p = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", app,
                 "--host", "127.0.0.1", "--port", str(port)],
                cwd=str(ROOT),
            )
            processes.append(p)

        print("\nAll agents started. Press Ctrl+C to stop.\n")
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
