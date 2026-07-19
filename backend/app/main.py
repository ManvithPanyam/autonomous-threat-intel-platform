from fastapi import FastAPI

app = FastAPI(title="Autonomous Threat Intelligence & Response Platform")

@app.get("/health")
def health():
    return {"status": "ok"}