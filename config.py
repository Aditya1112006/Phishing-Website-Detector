"""
config.py
---------
Centralized application configuration.
Loads environment variables from .env using python-dotenv with production-ready fallbacks.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

# Load local environment configuration from .env if present
load_dotenv(BASE_DIR / ".env")


class Config:
    """Application configuration parameters."""

    # Server & Security
    SECRET_KEY = os.getenv("SECRET_KEY", "phishguard-dev-secret-key-3f8a9e2c1b")
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = os.getenv("FLASK_DEBUG", "True").strip().lower() in ("true", "1", "yes")
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))

    # File & Model Paths
    MODEL_PATH = os.getenv("MODEL_PATH", str(BASE_DIR / "models" / "phishing_url_model.pkl"))
    FEATURES_PATH = os.getenv("FEATURES_PATH", str(BASE_DIR / "models" / "phishing_url_features.pkl"))
    DATA_PATH = os.getenv("DATA_PATH", str(BASE_DIR / "data" / "Phishing_Dataset.csv"))
    TRUSTED_DOMAINS_FILE = os.getenv("TRUSTED_DOMAINS_FILE", str(BASE_DIR / "data" / "supplement_legit.txt"))

    # Optional Threat Intelligence API Keys
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

    # Limits & Thresholds
    MAX_BATCH_URLS = int(os.getenv("MAX_BATCH_URLS", "25"))
