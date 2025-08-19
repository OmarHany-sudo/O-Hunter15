FROM python:3.11-slim

# تحديد مجلد العمل
WORKDIR /app

# تثبيت NodeJS 20 + pnpm
RUN apt-get update && apt-get install -y curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g pnpm \
    && rm -rf /var/lib/apt/lists/*

# تثبيت باكدجات Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# نسخ باقي ملفات المشروع
COPY . .

# ===== Build Frontend =====
WORKDIR /app/gui/ohunter-ui
RUN pnpm install --frozen-lockfile --prod && pnpm run build

# رجوع لمجلد الباك إند
WORKDIR /app

# تعيين متغيرات البيئة
ENV PYTHONPATH=/app
ENV PORT=8080

# فتح البورت
EXPOSE $PORT

# الأمر الافتراضي للتشغيل (ممكن تبدله بـ gunicorn في الإنتاج)
CMD ["python", "core/app.py"]
