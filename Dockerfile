FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FIXREPRO_CONTAINER_MODE=1

WORKDIR /opt/fixrepro

RUN adduser --disabled-password --gecos "" --uid 10001 fixrepro

COPY --chown=10001:10001 . .

RUN python -m pip install --no-cache-dir . \
    && mkdir -p .runtime/logs evidence/runs \
    && chown -R 10001:10001 .runtime evidence/runs

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).read()"]

CMD ["python", "scripts/run_dashboard.py", "--host", "0.0.0.0", "--port", "8000"]
