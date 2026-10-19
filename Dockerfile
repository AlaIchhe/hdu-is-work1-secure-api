FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/secure_api.db

WORKDIR /app

RUN groupadd --system app && useradd --system --gid app --create-home app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py ./
COPY secure_api ./secure_api
COPY docker-entrypoint.sh ./

RUN chmod +x docker-entrypoint.sh && mkdir -p /data && chown -R app:app /app /data

USER app

EXPOSE 5000

ENTRYPOINT ["./docker-entrypoint.sh"]
