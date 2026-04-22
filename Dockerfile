FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY auth_middleware.py .
COPY redaction.py .
COPY secrets_resolver.py .
COPY policy_and_approvals/ ./policy_and_approvals/
COPY static/ ./static/

CMD ["python", "main.py"]
