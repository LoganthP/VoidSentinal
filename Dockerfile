# syntax=docker/dockerfile:1
FROM node:22-alpine AS dashboard
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    VS_DATA_DIR=/data \
    VS_COOKIE_SECURE=true \
    VS_SIGNUP_ENABLED=false \
    VS_MAX_UPLOAD_MB=25 \
    OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/voidsentinel ./voidsentinel
COPY --from=dashboard /build/dist ./dashboard

# Register static files after the API routes to keep requests on one origin.
RUN <<'EOF'
cat > render_app.py <<'PY'
from starlette.exceptions import HTTPException
from starlette.staticfiles import StaticFiles

from voidsentinel.api import app


class DashboardFiles(StaticFiles):
    async def get_response(self, path, scope):
        try:
            return await super().get_response(path, scope)
        except HTTPException as exc:
            headers = dict(scope["headers"])
            if (
                exc.status_code == 404
                and path != "api"
                and not path.startswith(("api/", "assets/"))
                and b"text/html" in headers.get(b"accept", b"")
            ):
                return await super().get_response("index.html", scope)
            raise


app.mount("/", DashboardFiles(directory="dashboard", html=True), name="dashboard")
PY
EOF

EXPOSE 10000
CMD ["sh", "-c", "exec uvicorn render_app:app --host 0.0.0.0 --port \"${PORT:-10000}\""]
