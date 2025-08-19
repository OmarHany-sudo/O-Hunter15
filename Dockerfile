FROM python:3.11-slim

WORKDIR /app

# تثبيت المتطلبات الأساسية
RUN apt-get update && apt-get install -y \
    curl \
    nodejs \
    npm \
    gcc \
    libffi-dev \
    make \
    && npm install -g pnpm \
    && rm -rf /var/lib/apt/lists/*

# نسخ requirements.txt وتثبيت باكدجات Python
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install gunicorn


# نسخ باقي ملفات المشروع
COPY . .

# ===== Build Frontend =====
WORKDIR /app/gui/ohunter-ui
RUN pnpm install && pnpm run build

# رجوع لمجلد الباك إند
WORKDIR /app

ENV PYTHONPATH=/app
ENV PORT=8080

EXPOSE $PORT

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} core.app:app --log-level debug"]
