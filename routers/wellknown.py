from fastapi import APIRouter
from config import settings
from crypto import public_jwk

router = APIRouter()

@router.get("/.well-known/jwks.json")
def jwks():
    return {"keys": [public_jwk()]}

@router.get("/.well-known/did.json")
def did_document():
    # ตัวอย่าง did:web อย่างง่าย (ลิงก์ไป JWKS)
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": settings.issuer_did,
        "verificationMethod": [{
            "id": f"{settings.issuer_did}#{settings.issuer_kid}",
            "type": "JsonWebKey2020",
            "controller": settings.issuer_did,
            "publicKeyJwk": public_jwk()
        }],
        "assertionMethod": [f"{settings.issuer_did}#{settings.issuer_kid}"]
    }
