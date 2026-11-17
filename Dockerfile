FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Asia/Shanghai

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY pyproject.toml ./
RUN pip install --no-cache-dir --no-deps -e .

COPY config.example.yaml ./config.example.yaml

# config.yaml 与 .env 用 volume 挂进来，不要打进镜像
VOLUME ["/app/data"]
CMD ["python", "-m", "eipguard", "-c", "/app/config.yaml"]
