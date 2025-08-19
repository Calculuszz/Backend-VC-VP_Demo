# generate_keys.py
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# สร้างโฟลเดอร์ keys ถ้ายังไม่มี
os.makedirs("keys", exist_ok=True)

# สร้างกุญแจ EC P-256 (prime256v1)
private_key = ec.generate_private_key(ec.SECP256R1())

# บันทึก private key (PKCS#8, unencrypted)
with open("keys/ec-private.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,   # PKCS8 อ่านง่าย
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

# บันทึก public key
public_key = private_key.public_key()
with open("keys/ec-public.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

print("✅ Keys generated in ./keys/")
