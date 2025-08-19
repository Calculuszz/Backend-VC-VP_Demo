from typing import Dict, Tuple

# credential_id -> (jwt, revoked(bool), reason(str|None))
CREDENTIALS: Dict[str, Tuple[str, bool, str | None]] = {}
# สำหรับตัวอย่าง status list แบบง่าย
REVOKED: Dict[str, str | None] = {}
