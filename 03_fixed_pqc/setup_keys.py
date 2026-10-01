from pathlib import Path
import oqs

KEYS = Path(__file__).resolve().parent / "keys"
KEYS.mkdir(exist_ok=True)

alg = "ML-DSA-65"
safe = alg.replace("-", "_")
pub_path = KEYS / f"planner_{safe}_public.bin"
sec_path = KEYS / f"planner_{safe}_secret.bin"

if not sec_path.exists():
    with oqs.Signature(alg) as signer:
        public = signer.generate_keypair()
        secret = signer.export_secret_key()
    pub_path.write_bytes(public)
    sec_path.write_bytes(secret)
    print("Generated ML-DSA-65 planner identity.")
else:
    print("ML-DSA-65 planner identity already exists.")
