FROM python:3.14-slim AS stubs
RUN pip install --no-cache-dir --only-binary=:all: grpcio-tools==1.85.1
COPY proto/ext_mcp.proto /proto/ext_mcp.proto
RUN mkdir /gen && python -m grpc_tools.protoc -I/proto --python_out=/gen --grpc_python_out=/gen /proto/ext_mcp.proto

FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app:/app/gen
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt
COPY interceptor/ /app/interceptor/
COPY --from=stubs /gen/ /app/gen/
RUN useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin interceptor
USER 10002
ENTRYPOINT ["python", "-m", "interceptor"]
