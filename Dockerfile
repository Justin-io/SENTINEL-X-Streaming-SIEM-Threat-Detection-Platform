FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt pyproject.toml README.md ./
RUN pip install --no-cache-dir -r requirements.txt 'aiokafka>=0.12,<1' 'clickhouse-connect>=1.0,<2'
COPY sentinel_x ./sentinel_x
COPY rules ./rules
RUN useradd --create-home --uid 10001 sentinel && mkdir -p /var/lib/sentinel-x && chown -R sentinel:sentinel /app /var/lib/sentinel-x
USER sentinel
ENV SENTINEL_DATA_DIR=/var/lib/sentinel-x
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3)" || exit 1
CMD ["uvicorn","sentinel_x.api:app","--host","0.0.0.0","--port","8000"]
