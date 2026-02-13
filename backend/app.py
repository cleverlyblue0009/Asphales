"""Main FastAPI application for SurakshaAI Shield."""

import os
import sys
import time
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure the backend package root is on sys.path so relative imports work
# when running with `python app.py` from inside backend/
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

load_dotenv()

from api.routes import router, set_classifier  # noqa: E402
from services.classifier import HybridClassifier  # noqa: E402
from utils.logger import setup_logger  # noqa: E402

logger = setup_logger("app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("Starting SurakshaAI Shield backend")
    clf = HybridClassifier()
    set_classifier(clf)
    app.state.classifier = clf
    logger.info("Backend ready")
    yield
    logger.info("Shutting down SurakshaAI Shield backend")


app = FastAPI(
    title="SurakshaAI Shield",
    description="Phishing detection API for code-mixed Hindi-English messages",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    elapsed = (time.time() - start) * 1000
    logger.info(
        "%s %s — %d (%.1fms)",
        request.method,
        request.url.path,
        response.status_code,
        elapsed,
    )
    return response


# Global error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)},
    )


app.include_router(router)

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("API_PORT", "8000"))
    logger.info("Starting server on port %d", port)
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
