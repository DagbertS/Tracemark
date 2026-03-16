FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.yaml /app/config.yaml
COPY app/ /app/app/

# Create persistent data directory (mount Railway volume here)
RUN mkdir -p /data

# Railway sets PORT dynamically; fallback to 8080 for local dev
ENV PORT=8080
EXPOSE ${PORT}

CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT}
