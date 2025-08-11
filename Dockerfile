FROM python:3.11-slim AS backend

# تحديد مجلد العمل
WORKDIR /app

# تثبيت المتطلبات الأساسية
RUN apt-get update && apt-get install -y \
    curl \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# تثبيت باكدجات Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# نسخ باقي ملفات المشروع
COPY . .

# ===== Build Frontend =====
WORKDIR /app/gui/ohunter-ui
RUN npm install && npm run build

# رجوع لمجلد الباك إند
WORKDIR /app

# إنشاء مستخدم غير الجذر
RUN useradd -m -u 1000 ohunter && chown -R ohunter:ohunter /app
USER ohunter

# جعل الاستضافة تقرأ البورت من متغير البيئة
ENV PORT=5000
EXPOSE $PORT

# الأمر الافتراضي للتشغيل
CMD ["python", "core/app.py"]
