# Образ backend: один и тот же для api и worker (различаются командой запуска в docker-compose.yml).
# Сборка из корня репозитория, потому что нужен пакет core: docker compose build api
FROM python:3.12-slim

# Колесо torch только для CPU (~200 МБ вместо ~2 ГБ сборки с CUDA)
ARG TORCH_INDEX=https://download.pytorch.org/whl/cpu

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/tmp

# libgomp1 нужен LightGBM; больше системных пакетов не ставим
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install torch --index-url "${TORCH_INDEX}"

WORKDIR /app
COPY core/ core/
RUN pip install ./core
COPY backend/ backend/
RUN pip install ./backend

# Непривилегированный пользователь; папка карантина принадлежит ему,
# и Docker скопирует владельца в новый том при первом запуске
RUN useradd --system --uid 10001 --no-create-home malscan \
    && mkdir -p /data/quarantine \
    && chown malscan:malscan /data/quarantine
USER malscan

WORKDIR /app/backend
ENV QUARANTINE_DIR=/data/quarantine \
    MODELS_DIR=/models \
    DEMO_DIR=/demo

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
