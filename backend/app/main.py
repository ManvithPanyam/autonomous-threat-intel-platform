from fastapi import FastAPI
from app.db.session import engine
from app.models import Base
from app.api.routes.alerts import router as alerts_router

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Autonomous Threat Intelligence & Response Platform")

app.include_router(alerts_router, prefix="/api/v1/alerts", tags=["alerts"])

@app.get("/health")
def health():
    return {"status": "ok"}