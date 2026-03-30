FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends tzdata && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /data

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

ENV PORT=5001 \
    DATABASE_URL=sqlite:////data/firewall_review.db

EXPOSE 5001

CMD ["gunicorn", "-w", "3", "-b", "0.0.0.0:5001", "app:app"]
