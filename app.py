"""FastAPI server. Run: uvicorn app:app --host 127.0.0.1 --port 8000"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from scamshield.pipeline import analyze

app = FastAPI(title="ScamShield India", docs_url=None, redoc_url=None)


class Req(BaseModel):
    message: str = Field("", max_length=4000)
    url: str = Field("", max_length=2048)
    use_ai: bool = True


@app.post("/api/analyze")
def analyze_endpoint(req: Req):
    try:
        return analyze(req.message, req.url, req.use_ai)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/")
def home():
    return FileResponse("static/index.html")


app.mount("/static", StaticFiles(directory="static"), name="static")
