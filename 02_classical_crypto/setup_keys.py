from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

KEYS = Path(__file__).resolve().parent / "keys"
KEYS.mkdir(exist_ok=True)

priv_path = KEYS / "planner_ed25519_private.raw"
pub_path = KEYS / "planner_ed25519_public.raw"

if not priv_path.exists():
    priv = Ed25519PrivateKey.generate()
    priv_path.write_bytes(priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    pub_path.write_bytes(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    print("Generated planner Ed25519 identity.")
else:
    print("Planner Ed25519 identity already exists.")
