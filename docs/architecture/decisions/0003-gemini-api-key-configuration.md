# ADR 0003: Gemini API Key Configuration

## Status
Accepted

## Context
The platform leverages the Gemini API to produce explainable threat scoring and incident summaries. Access to this external model requires a private API key, which must be loaded securely into both the FastAPI application and asynchronous Celery workers.

## Decision
We will store the `GEMINI_API_KEY` in the local, gitignored `.env` file. 
- The config is loaded using `python-dotenv` inside the application settings.
- In `docker-compose.yml`, the `.env` file is loaded into the `backend` environment, ensuring both FastAPI routes and Celery workers (running within the same backend container environment) have access to `os.getenv("GEMINI_API_KEY")`.

## Alternatives considered
- **Hardcoded API Keys**: Extreme security risk of pushing secrets to public source control.
- **FastAPI Endpoint Injection**: Requiring the client to supply the key in request headers. This is insecure and impractical for automated, asynchronous backend workers.

## Consequences
- Clean separation of configuration from code.
- Keys are kept secure and out of git history.
- Easy key rotation by modifying the local `.env` file.
