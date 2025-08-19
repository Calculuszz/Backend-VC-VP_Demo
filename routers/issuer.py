from fastapi import APIRouter, HTTPException
from models import IssueRequest, IssuedCredential, RevokeRequest, RevocationStatus
from services.issuance import issue_vc
from services.revocation import revoke_credential, get_revocation_status

router = APIRouter()

@router.post("/credentials", response_model=IssuedCredential)
def issue_credential(req: IssueRequest):
    vc_id, token = issue_vc(
        subject_id=req.subject_id,
        schema=req.schema,
        claims=req.claims,
        expires_at=req.expires_at,
        status_list_index=req.status_list_index,
    )
    return {"id": vc_id, "jwt": token}

@router.post("/credentials/revoke", response_model=RevocationStatus)
def revoke(req: RevokeRequest):
    ok = revoke_credential(req.credential_id, req.reason)
    if not ok:
        raise HTTPException(status_code=404, detail="Credential not found")
    status = get_revocation_status(req.credential_id)
    return status

@router.get("/credentials/{credential_id}/status", response_model=RevocationStatus)
def check_status(credential_id: str):
    status = get_revocation_status(credential_id)
    if not status:
        raise HTTPException(status_code=404, detail="Credential not found")
    return status
