FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent/ /app/agent/
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin agent
USER 10001
CMD ["python", "-m", "agent"]
