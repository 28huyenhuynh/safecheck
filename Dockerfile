# SafeCheck web app. Works on Render, Hugging Face Spaces (Docker) and any Docker host.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
# Retrain inside the image so the saved model matches this scikit-learn version
RUN python train.py && python tests/test_detector.py

# Render sets $PORT; Hugging Face Spaces expects 7860
ENV PORT=7860
EXPOSE 7860
CMD uvicorn app:app --host 0.0.0.0 --port $PORT
