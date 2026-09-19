"""FastAPI application entry point.

Run (from backend/):  uvicorn app.main:app --reload --port 8000
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from . import db
from .api import router

app = FastAPI(
    title="Intelligent Cyber Situational Awareness",
    description="Training-environment mini-SIEM: ingest → classify → correlate → "
                "AI analysis → prioritize → visualize → report.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # training tool, local use only
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.on_event("startup")
def _startup():
    db.init_db()


@app.get("/api/health")
def health():
    return {"status": "ok", "events": db.count_events()}


# Serve the built frontend (frontend/dist) if present, so the whole app is one server.
_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if _DIST.exists():
    app.mount("/", StaticFiles(directory=str(_DIST), html=True), name="frontend")
