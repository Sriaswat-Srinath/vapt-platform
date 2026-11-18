# syntax=docker/dockerfile:1
# API image. Debian slim (not alpine): psycopg ships manylinux wheels only.
FROM python@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv

COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r /srv/requirements.txt

COPY alembic.ini /srv/alembic.ini
COPY migrations /srv/migrations
COPY app /srv/app
COPY fixtures /srv/fixtures

# Non-root. The app writes nothing to disk.
USER 65532:65532
EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn app.main:app --host ${API_BIND_IP:-0.0.0.0} --port ${API_PORT:-8000} --proxy-headers --no-server-header"]
