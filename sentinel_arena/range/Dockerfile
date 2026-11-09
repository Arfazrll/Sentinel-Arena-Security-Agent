# Bundled vulnerable app for the Docker-backed range.
# Intentionally weak app, but run with no internet route (see docker-compose /
# DockerRange internal network) and on 0.0.0.0 inside its own container only.
FROM python:3.12-slim

WORKDIR /app
# Only the package is needed; the app uses the stdlib, no third-party deps.
COPY sentinel_arena /app/sentinel_arena
COPY pyproject.toml /app/pyproject.toml

ENV PYTHONUNBUFFERED=1 \
    ARENA_PORT=8080

EXPOSE 8080
# -I: isolated mode, so nothing is imported from the working directory beyond
# our package path.
CMD ["python", "-I", "-m", "sentinel_arena.range.serve"]
