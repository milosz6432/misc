# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml ./
COPY hunterintel ./hunterintel
RUN pip wheel --wheel-dir /wheels .

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin hunterintel
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links=/wheels hunterintel && rm -rf /wheels
COPY alembic.ini ./
COPY alembic ./alembic
# SQLite (if used) and any user-supplied GeoIP database live under /data
RUN mkdir -p /data && chown hunterintel:hunterintel /data
VOLUME ["/data"]
USER hunterintel
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3).status == 200 else 1)"
# Migrate, then serve. `--proxy-headers` makes per-client rate limiting see the real client IP
# when running behind the bundled nginx (the API port is never published to the host).
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn hunterintel.api.app:app_factory --factory --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'"]
