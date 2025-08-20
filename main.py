from fastapi import FastAPI
from routers import issuer, wellknown, verifier
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="VC Issuer API (Python FastAPI)",
    version="0.1.0",
    description="MVP สำหรับออก JWT-VC + JWKS + revocation (simple)"
)

app.include_router(issuer.router, prefix="/issuer", tags=["issuer"])
app.include_router(wellknown.router, tags=["well-known"])
app.include_router(verifier.router, prefix="/verifier", tags=["verifier"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://vc-vp-demo-production.up.railway.app",
        "https://backend-vc-vpdemo-production.up.railway.app",
    ],  # หรือใส่โดเมนโปรดักชัน
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"ok": True, "service": "issuer", "docs": "/docs"}
