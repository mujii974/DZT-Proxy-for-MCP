# scripts/gen_es256k_keys_to_files.py
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
KEY_DIR = ROOT / "did" / "keys"

def main():
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    # Generate secp256k1 keypair (ES256K)
    priv = ec.generate_private_key(ec.SECP256K1())

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    (KEY_DIR / "agent1_private.pem").write_text(priv_pem)
    (KEY_DIR / "agent1_public.pem").write_text(pub_pem)

    print("Wrote:")
    print(" - did/keys/agent1_private.pem")
    print(" - did/keys/agent1_public.pem")
    print("\nPUBLIC KEY (paste into DID doc if needed):\n")
    print(pub_pem)

if __name__ == "__main__":
    main()
