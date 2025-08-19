from datetime import datetime
from typing import Dict, Any, Optional
from crypto import sign_jwt_vc
from storage import CREDENTIALS

def issue_vc(
    subject_id: str,
    schema: str,
    claims: Dict[str, Any],
    expires_at: Optional[datetime],
    status_list_index: Optional[int],
):
    vc_id, token = sign_jwt_vc(subject_id, claims, schema, expires_at, status_list_index)
    CREDENTIALS[vc_id] = (token, False, None)
    return vc_id, token
