import os
from dotenv import load_dotenv

# Load env file in case it is run from command line directly
load_dotenv()

class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+psycopg://threatintel:change_me@postgres:5432/threatintel")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://redis:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/1")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY")
    VT_API_KEY: str = os.getenv("VT_API_KEY")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY")

settings = Settings()
