from metrics.collector import RESULT_FILE

if RESULT_FILE.exists():
    RESULT_FILE.unlink()
    print(f"Deleted {RESULT_FILE}")
else:
    print(f"No result file yet: {RESULT_FILE}")
