FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt
COPY mcp_server/ /app/mcp_server/
RUN useradd --uid 10003 --no-create-home --shell /usr/sbin/nologin mcp
USER 10003
ENTRYPOINT ["python", "-m", "mcp_server"]
