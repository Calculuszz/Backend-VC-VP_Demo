import time, uuid, json, base64
from jose import jwt
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from config import settings
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def _read_private_pem():
    with open(settings.private_key_path, "rb") as f:
        return f.read()  # jose รับเป็น bytes/str PEM ได้

def _load_public_key():
    with open(settings.public_key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def sign_jwt_vc(
    sub: str,
    claims: Dict[str, Any],
    schema: str,
    expires_at: Optional[datetime] = None,
    status_list_index: Optional[int] = None,
) -> tuple[str, str]:
    """
    คืนค่า (credential_id, jwt_string)
    ใช้โมเดล JWT-VC (W3C VC Data Model แบบ JWS)
    """
    now = int(time.time())
    jti = "vc_" + uuid.uuid4().hex
    kid_full = f"{settings.issuer_did}#{settings.issuer_kid}"

    payload = {
        "iss": settings.issuer_did,
        "sub": sub,
        "nbf": now,
        "iat": now,
        "jti": jti,
        "vc": {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", schema],
            "credentialSubject": claims,
        },
    }
    if expires_at:
        payload["exp"] = int(expires_at.replace(tzinfo=timezone.utc).timestamp())
    if status_list_index is not None:
        payload["vc"]["credentialStatus"] = {
            "id": f"{settings.issuer_did}/status/{jti}",
            "type": "StatusList2021Entry",
            "statusPurpose": "revocation",
            "statusListIndex": str(status_list_index),
            "statusListCredential": f"{settings.issuer_did}/statuslists/revocation/2021"
        }

    headers = {"kid": f"{settings.issuer_did}#{settings.issuer_kid}",
               "alg": settings.jwt_alg, "typ": "JWT"}
    token = jwt.encode(payload, _read_private_pem(), algorithm=settings.jwt_alg, headers=headers)
    return jti, token

def public_jwk():
    """
    ส่งคืน JWK (เฉพาะ ES256/EdDSA ที่ระบุไว้ใน .env)
    หมายเหตุ: เพื่อความง่าย เราใช้ PEM -> cryptography -> JWK ได้ด้วย lib เสริม
    ที่นี่จะแปลงแบบง่ายสำหรับ ES256 (P-256) เป็นตัวอย่าง
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend

    pub = serialization.load_pem_public_key(
        settings.public_key_pem.encode(), backend=default_backend()
    )
    if isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        x = nums.x.to_bytes(32, "big")
        y = nums.y.to_bytes(32, "big")
        return {
            "kty": "EC",
            "crv": "P-256",
            "kid": settings.issuer_kid,
            "alg": settings.jwt_alg,
            "use": "sig",
            "x": _b64url(x),
            "y": _b64url(y),
        }
    # (ถ้าใช้ Ed25519: แนะนำใช้ libsodium/cryptography เพื่อดึง raw pubkey แล้วทำ JWK 'OKP')
    raise ValueError("Unsupported key type for example jwk builder")
