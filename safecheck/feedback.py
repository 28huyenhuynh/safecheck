"""Save user feedback from the web page.

Locally, answers are appended to data/feedback.csv. Free hosts (Hugging Face Spaces, Render, Vercel)
erase local files on restart, so when FEEDBACK_WEBHOOK_URL is set, answers are sent there instead
(for example a Google Apps Script web app that adds a row to a Google Sheet, see README).
The checked message itself is never part of the feedback.
"""
import csv
import json
import os
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ["time", "kind", "level", "score", "correct",
          "accuracy", "wrong_example", "clarity", "would_use", "signs", "signs_other", "ideas"]
CSV_PATH = Path(__file__).resolve().parent.parent / "data" / "feedback.csv"
_lock = threading.Lock()


def _safe(value):
    # Stop spreadsheet apps from running text like "=HYPERLINK(...)" as a formula
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@"):
        return "'" + value
    return value


def save(answers: dict) -> None:
    row = {k: _safe(answers.get(k)) if answers.get(k) is not None else "" for k in FIELDS}
    row["time"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    url = os.environ.get("FEEDBACK_WEBHOOK_URL")
    if url:
        req = urllib.request.Request(url, data=json.dumps(row, ensure_ascii=False).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10):
            pass
        return

    with _lock:
        new = not CSV_PATH.exists()
        with CSV_PATH.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            if new:
                writer.writeheader()
            writer.writerow(row)
