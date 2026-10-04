# AI-Powered Cybersecurity Incident Investigation & Response Platform

A final-year AI & Data Science project that demonstrates an end-to-end SOC workflow:

Security events → ML detection → alerts → incident correlation → investigation → RAG/agentic reasoning → risk → human approval → dashboard.

## Current milestone
Foundation + sample event pipeline. The project is intentionally built incrementally so each component can be tested and understood before adding the next one.

## Structure
- `backend/` FastAPI application
- `ml/` model/training components
- `data/sample/` safe synthetic events for local development
- `knowledge_base/` documents for the future RAG layer
- `frontend/` dashboard placeholder
- `docs/` architecture and build status
- `scripts/` utilities

## Run
Create a virtual environment and install:
`pip install -r backend/requirements.txt`

Start API:
`uvicorn backend.app.main:app --reload`

Health check:
`GET http://127.0.0.1:8000/health`

Events:
`GET http://127.0.0.1:8000/api/events`

No real credentials or offensive security tooling are included.
