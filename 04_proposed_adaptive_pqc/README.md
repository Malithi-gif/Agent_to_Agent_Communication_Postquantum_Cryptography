# 04 Proposed Adaptive PQC

Policy:
- LOW: ML-KEM-512 + AES-256-GCM, no ML-DSA
- MEDIUM: ML-KEM-768 + ML-DSA-65 + AES-256-GCM + audit
- CRITICAL: ML-KEM-1024 + ML-DSA-87 + AES-256-GCM + delegation token + audit

Run:
`python -m pip install -r requirements.txt`
`python reset_results.py`
`python run_all.py`
Second terminal: `python test_task.py`

Output: `metrics/results_adaptive_pqc.csv`
Audit log: `audit/audit.jsonl`

liboqs-python may build liboqs automatically on first import. Git, CMake, and a C/C++ compiler are required.
