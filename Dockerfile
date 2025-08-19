FROM python:3.11-slim

WORKDIR /app

# تثبيت requirements + build tools
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install gunicorn

# نسخ المشروع
COPY . .

# Build Frontend (React)
WORKDIR /app/gui/ohunter-ui
RUN npm install && npm run build

# Back to backend
WORKDIR /app

ENV PYTHONPATH=/app
ENV PORT=8080

EXPOSE $PORT

# Gunicorn command
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "core.app:app"]
