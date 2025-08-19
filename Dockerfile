FROM python:3.11-slim

WORKDIR /app

# تثبيت المتطلبات الأساسية
RUN apt-get update && apt-get install -y \
    curl \
    nodejs \
    npm \
    && npm install -g pnpm \
    && rm -rf /var/lib/apt/lists/*

# requirements + gunicorn
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install gunicorn

# نسخ باقي الملفات
COPY . .

# Build Frontend
WORKDIR /app/gui/ohunter-ui
RUN pnpm install && pnpm run build

# رجوع للباك إند
WORKDIR /app

# Variables
ENV PYTHONPATH=/app
ENV PORT=8080

EXPOSE $PORT

# Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "core.app:app"]
