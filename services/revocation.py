from storage import CREDENTIALS, REVOKED

def revoke_credential(credential_id: str, reason: str | None = None):
    if credential_id not in CREDENTIALS:
        return False
    token, _, _ = CREDENTIALS[credential_id]
    CREDENTIALS[credential_id] = (token, True, reason)
    REVOKED[credential_id] = reason
    return True

def get_revocation_status(credential_id: str):
    if credential_id not in CREDENTIALS:
        return None
    token, revoked, reason = CREDENTIALS[credential_id]
    return {"credential_id": credential_id, "revoked": revoked, "reason": reason}
