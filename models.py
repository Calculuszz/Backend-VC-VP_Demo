from pydantic import BaseModel, Field
from typing import Optional, Any, Dict, List
from datetime import datetime

class IssueRequest(BaseModel):
    subject_id: str
    schema: str = "HealthPass"
    claims: Dict[str, Any] = Field(default_factory=dict)
    expires_at: Optional[datetime] = None
    status_list_index: Optional[int] = None

class IssuedCredential(BaseModel):
    id: str
    jwt: str
    format: str = "jwt_vc"

class RevokeRequest(BaseModel):
    credential_id: str
    reason: Optional[str] = None

class RevocationStatus(BaseModel):
    credential_id: str
    revoked: bool
    reason: Optional[str] = None

class JWKSKey(BaseModel):
    kty: str
    kid: str
    alg: str
    use: str = "sig"
    crv: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None

class JWKS(BaseModel):
    keys: List[JWKSKey]
