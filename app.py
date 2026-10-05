"""SafeCheck web app.

Run:   uvicorn app:app --reload
Open:  http://127.0.0.1:8000
"""
import logging
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from safecheck import feedback
from safecheck.detector import Detector

BASE = Path(__file__).resolve().parent
app = FastAPI(title="SafeCheck", description="Kiểm tra tin nhắn lừa đảo")
detector = Detector()


class CheckRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=3000)


@app.post("/api/check")
def check(req: CheckRequest) -> dict:
    # Nothing is stored or logged: the message is checked in memory and discarded.
    try:
        return detector.check(req.text)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


Rating = Optional[int]


class FeedbackRequest(BaseModel):
    # "result": the yes/no question under a result. "survey": the form at the bottom of the page.
    kind: Literal["result", "survey"]
    level: Optional[Literal["low", "medium", "high"]] = None
    score: Optional[int] = Field(None, ge=0, le=100)
    correct: Optional[Literal["yes", "no", "unsure"]] = None
    accuracy: Optional[Literal["all", "most", "many_wrong", "unsure"]] = None
    wrong_example: Optional[str] = Field(None, max_length=500)
    clarity: Rating = Field(None, ge=1, le=5)
    would_use: Optional[Literal["yes", "no", "unsure"]] = None
    signs: Optional[str] = Field(None, max_length=200)
    signs_other: Optional[str] = Field(None, max_length=200)
    ideas: Optional[str] = Field(None, max_length=1000)


@app.post("/api/feedback")
def give_feedback(req: FeedbackRequest) -> dict:
    try:
        feedback.save(req.model_dump())
    except Exception:
        logging.exception("Could not save feedback")
        raise HTTPException(status_code=503, detail="Feedback could not be saved")
    return {"ok": True}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(BASE / "static" / "index.html")
