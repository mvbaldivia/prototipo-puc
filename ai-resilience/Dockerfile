FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ai-resilience/ /app/ai-resilience/
ENV PYTHONPATH=/app

CMD ["python", "-m", "ai-resilience.validator"]
