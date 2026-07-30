from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db.session import engine
from app.models import Base
from app.api.routes.alerts import router as alerts_router
from app.api.routes.cases import router as cases_router
from app.api.routes.actions import router as actions_router

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Autonomous Threat Intelligence & Response Platform")

# CORS Configuration for Analyst Frontend Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-User-Role", "X-User-ID"],
)

app.include_router(alerts_router, prefix="/api/v1/alerts", tags=["alerts"])
app.include_router(cases_router, prefix="/api/v1/cases", tags=["cases"])
app.include_router(actions_router, prefix="/api/v1", tags=["actions"])

@app.get("/health")
def health():
    return {"status": "ok"}