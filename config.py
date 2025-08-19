# config.py
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent  # โฟลเดอร์เดียวกับ config.py

class Settings(BaseSettings):
    issuer_did: str = Field(..., alias="ISSUER_DID")
    issuer_kid: str = Field(..., alias="ISSUER_KID")

    private_key_pem: str | None = Field(None, alias="PRIVATE_KEY_PEM")
    public_key_pem: str | None  = Field(None, alias="PUBLIC_KEY_PEM")
    private_key_path: Path | None = Field(None, alias="PRIVATE_KEY_PATH")
    public_key_path: Path | None  = Field(None, alias="PUBLIC_KEY_PATH")

    jwt_alg: str = Field("ES256", alias="JWT_ALG")  # ✅ เพิ่มบรรทัดนี้
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env.example"),   # ใช้ path ตายตัว
        env_prefix="",
        extra="ignore",
        case_sensitive=False,              # กันเคสผิด
    )

    def load_key_material(self):
        if self.private_key_pem is None and self.private_key_path and self.private_key_path.exists():
            self.private_key_pem = self.private_key_path.read_text(encoding="utf-8")
        if self.public_key_pem is None and self.public_key_path and self.public_key_path.exists():
            self.public_key_pem = self.public_key_path.read_text(encoding="utf-8")
        if self.private_key_pem and "\\n" in self.private_key_pem:
            self.private_key_pem = self.private_key_pem.replace("\\n", "\n")
        if self.public_key_pem and "\\n" in self.public_key_pem:
            self.public_key_pem = self.public_key_pem.replace("\\n", "\n")
        return self 
                

    

settings = Settings().load_key_material()


