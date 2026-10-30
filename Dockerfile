# Single-service image: FastAPI serves the API and the built React UI on $PORT.
# Defaults to replay mode (no API key needed). Set GROQ_API_KEY as a secret for live runs.

FROM node:22-slim AS ui
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    LLM_MODE=replay \
    PLANNER_MODE=permissive \
    PORT=8000
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ backend/
COPY docs/results.json docs/results.json
COPY --from=ui /app/frontend/dist frontend/dist
# Run as an unprivileged user; it only needs to write the audit log and outbox inside backend/.
RUN useradd --create-home leash && chown -R leash /app/backend
USER leash
EXPOSE 8000
CMD ["sh", "-c", "uvicorn backend.server:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
