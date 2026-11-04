#!/bin/bash
set -e

echo "🚀 [1/2] Đang khởi động AI Guardrail Proxy (Port 11435)..."
python proxy_server.py &

echo "🚀 [2/2] Đang khởi động Streamlit Dashboard (Port 8501)..."
streamlit run app.py --server.port=8501 --server.address=0.0.0.0