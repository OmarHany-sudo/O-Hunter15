FROM python:3.11-slim

# تحديد مجلد العمل
WORKDIR /app

# تثبيت المتطلبات الأساسية
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# تثبيت باكدجات Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# نسخ باقي ملفات المشروع
COPY . .

# إنشاء مستخدم غير الجذر
RUN useradd -m -u 1000 ohunter && chown -R ohunter:ohunter /app
USER ohunter

# جعل الاستضافة تقرأ البورت من متغير البيئة
EXPOSE $PORT

# الأمر الافتراضي للتشغيل
CMD ["python", "core/app.py"]
