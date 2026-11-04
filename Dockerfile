FROM python:3.12-slim

# Cài đặt công cụ hệ thống và Tesseract OCR (vie + eng)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-vie \
    tesseract-ocr-eng \
    libpq-dev \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy và cài đặt thư viện Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ mã nguồn vào Container
COPY . .

# Phân quyền thực thi cho kịch bản chạy
RUN chmod +x entrypoint.sh

# Mở các cổng: 8501 (Streamlit Web), 11435 (Proxy Firewall)
EXPOSE 8501 11435

CMD ["./entrypoint.sh"]