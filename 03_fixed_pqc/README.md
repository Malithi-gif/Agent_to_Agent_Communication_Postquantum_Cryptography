# 03 Fixed PQC

Every request uses:
ML-KEM-768 + ML-DSA-65 + HKDF-SHA256 + AES-256-GCM.

Run:
`python -m pip install -r requirements.txt`
`python reset_results.py`
`python run_all.py`
Second terminal: `python test_task.py`

Output: `metrics/results_fixed_pqc.csv`

liboqs-python may build liboqs automatically on first import. Git, CMake, and a C/C++ compiler are required.
