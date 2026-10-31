FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_ENV=production
# APP_ENV=production fails closed: the app refuses to start until APP_SECRET_KEY is injected
# (ECS secrets / SSM). docker-compose overrides it to "local". Users are created with
# `python -m scripts.create_user` (one-off task); there is no shared login.

WORKDIR /srv/aegis

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

# .dockerignore is an allowlist (app, alembic, scripts, the demo fixture, requirements, licences):
# nothing else in the working tree, case data and .env included, reaches the image
COPY . .

# Non-root runtime user (ECS/Fargate best practice)
RUN useradd -r -u 10001 aegis && chown -R aegis:aegis /srv/aegis
USER aegis

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://localhost:8000/healthz || exit 1

# Behind the ALB: trust X-Forwarded-For only from the load balancer's subnet, so the login rate
# limiter and the audit log see the real client IP (uvicorn reads FORWARDED_ALLOW_IPS). Set it in
# the task definition to the ALB subnet CIDRs; the default trusts only localhost.
ENV FORWARDED_ALLOW_IPS=127.0.0.1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
