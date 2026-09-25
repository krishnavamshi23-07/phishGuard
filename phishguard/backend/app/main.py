from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlmodel import SQLModel, create_engine
import time
from collections import defaultdict

from app.config import settings
from app.routers import urls, emails, reports

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Layered Anti-Phishing API combining Rule Heuristics, Threat Blocklists, and Machine Learning.",
)

# CORS middleware for Next.js frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory sliding window rate limiter
_request_counts = defaultdict(list)


@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    if request.url.path.startswith("/api"):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - 60.0

        # Filter timestamps in past 60s
        _request_counts[client_ip] = [t for t in _request_counts[client_ip] if t > window_start]

        if len(_request_counts[client_ip]) >= settings.RATE_LIMIT_PER_MINUTE:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded. Maximum 60 requests per minute."},
            )

        _request_counts[client_ip].append(now)

    response = await call_next(request)
    return response


@app.on_event("startup")
def on_startup():
    try:
        # Create database tables if database engine is configured
        engine = create_engine(settings.DATABASE_URL, echo=False)
        SQLModel.metadata.create_all(engine)
    except Exception as e:
        print(f"[*] Note: Database connection deferred or not ready: {e}")


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "PhishGuard Backend",
        "layers": ["rules", "reputation", "ml_model"],
    }


# Include Routers
app.include_router(urls.router, prefix=settings.API_V1_STR)
app.include_router(emails.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)
