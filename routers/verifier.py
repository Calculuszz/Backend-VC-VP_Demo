# routers/verifier.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import requests
from jose import jwt, jwk

JWKS_URL = "https://backend-vc-vpdemo-production.up.railway.app/.well-known/jwks.json"  # เปลี่ยนเป็นโปรดักชันตอน deploy

router = APIRouter()

class VerifyIn(BaseModel):
    jwt: str

@router.post("/verify")
def verify(in_: VerifyIn):
    token = in_.jwt.strip()

    # 1) ตรวจรูปแบบ JWT เบื้องต้น
    parts = token.split(".")
    if len(parts) != 3:
        return {"valid": False, "reason": "รูปแบบ JWT ไม่ถูกต้อง (ต้องมี 3 ส่วนคั่นด้วยจุด)"}

    try:
        # 2) อ่าน header แบบไม่ถอดลายเซ็น (ปลอดภัยกว่า base64 เอง)
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg", "ES256")
        if not kid:
            return {"valid": False, "reason": "JWT header ไม่มี kid"}

        # 3) โหลด JWKS
        try:
            r = requests.get(JWKS_URL, timeout=5)
            r.raise_for_status()
            jwks = r.json().get("keys", [])
        except Exception as e:
            return {"valid": False, "reason": f"โหลด JWKS ไม่สำเร็จ: {e}"}

        # 4) หา key ที่ตรงกับ kid (รองรับทั้ง kid เต็ม/ตัดหลัง #)
        short_kid = kid.split("#")[-1]
        key = next((k for k in jwks if k.get("kid") in (kid, short_kid)), None)
        if not key:
            return {"valid": False, "reason": "ไม่พบคีย์ที่ตรงกับ kid ใน JWKS"}

        # 5) ถอด JWT และตรวจลายเซ็น
        #    jose จะตรวจ exp/nbf/iat ให้อัตโนมัติถ้ามีใน payload
        payload = jwt.decode(token, key, algorithms=[alg])

        # TODO: เสริมเช็คตามระบบจริง:
        # - ตรวจ revoked / status registry
        # - ตรวจ aud/iss/sub ให้ตรงระบบ
        # - ตรวจ schema/VC fields ตามที่ต้องการ

        return {"valid": True, "payload": payload}

    except Exception as e:
        # รวม ๆ แล้วไม่ผ่าน
        return {"valid": False, "reason": str(e)}
