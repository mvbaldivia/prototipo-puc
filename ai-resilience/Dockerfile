FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ai-resilience/ /app/ai-resilience/
ENV PYTHONPATH=/app

CMD ["python", "-c", "import time; print('ai-resilience worker ready (OCSF v1.9.0 - 6003)', flush=True); time.sleep(86400)"]
