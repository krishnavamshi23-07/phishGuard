import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    PROJECT_NAME: str = "PhishGuard API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"

    # PostgreSQL Database URL (SQLModel / SQLAlchemy)
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql://phishguard_user:password@localhost:5432/phishguard_db",
    )

    # External Reputation APIs
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    PHISHTANK_API_KEY: Optional[str] = os.getenv("PHISHTANK_API_KEY", "")

    # ML Model Configuration
    ML_MODEL_PATH: str = os.getenv("ML_MODEL_PATH", "models/rf_phishing_model.joblib")

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

    # CORS Configuration
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "*"
    ]

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
