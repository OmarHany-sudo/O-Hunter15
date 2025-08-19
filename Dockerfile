FROM python:3.11-slim

# تحديد مجلد العمل
WORKDIR /app

# تثبيت المتطلبات الأساسية
RUN apt-get update && apt-get install -y \
    curl \
    nodejs \
    npm \
    && npm install -g pnpm \
    && rm -rf /var/lib/apt/lists/*

# تثبيت باكدجات Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# نسخ باقي ملفات المشروع
COPY . .

# ===== Build Frontend =====
WORKDIR /app/gui/ohunter-ui
RUN pnpm install && pnpm run build

# رجوع لمجلد الباك إند
WORKDIR /app

# تعيين متغيرات البيئة
ENV PYTHONPATH=/app
ENV PORT=8080

# فتح البورت
EXPOSE $PORT

# تشغيل Gunicorn (Production)
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} core.app:app"]
