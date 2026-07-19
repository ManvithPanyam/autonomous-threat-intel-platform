from fastapi import FastAPI
from app.db.session import engine
from app.models import Base

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Autonomous Threat Intelligence & Response Platform")

@app.get("/health")
def health():
    return {"status": "ok"}