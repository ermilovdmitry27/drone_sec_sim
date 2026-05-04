FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY security_agent/ ./security_agent/
COPY monitor.py launch_stack.py threat_coverage.py ./
COPY scenarios/ ./scenarios/
COPY tools/ ./tools/
COPY tests/ ./tests/
COPY Makefile .env.example ./

RUN mkdir -p logs

ENV PYTHONPATH=/app
ENV LOG_DIR=/app/logs

CMD ["python", "monitor.py", "--help"]
