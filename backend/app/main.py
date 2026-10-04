from fastapi import FastAPI

from backend.app.api.events import router as events_router
from backend.app.api.approval import router as approval_router
from backend.app.api.incidents import router as incidents_router


app = FastAPI(
    title="AI Cybersecurity SOC Platform",
    version="0.1.0",
    description=(
        "AI-assisted security event detection "
        "and incident investigation platform."
    ),
)


app.include_router(
    events_router,
    prefix="/api",
)


app.include_router(
    approval_router,
    prefix="/api",
)
app.include_router(
    incidents_router,
    prefix="/api",
)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ai-cyber-soc",
    }