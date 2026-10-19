#!/bin/sh
set -eu

flask --app app init-db

exec gunicorn \
    --bind 0.0.0.0:5000 \
    --workers "${GUNICORN_WORKERS:-2}" \
    --access-logfile - \
    --error-logfile - \
    app:app
