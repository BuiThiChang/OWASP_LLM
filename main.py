"""
FILE: main.py
Mô tả: Bộ khởi chạy hệ thống tích hợp (Ollama Core 11436 + Proxy 11435 + Streamlit 8501).
- Tự động nạp cấu hình Keep-Alive và mô hình Judge nhẹ llama3.2:1b
"""
import subprocess
import time
import sys
import os

def run_system():
    print("🚀 Đang khởi động LLMVault Security Suite...")

    # Cấu hình biến môi trường đồng bộ
    env = os.environ.copy()
    env["OLLAMA_HOST"] = "127.0.0.1:11436"
    env["OLLAMA_KEEP_ALIVE"] = "-1"
    env["AI_JUDGE_MODEL"] = "llama3.2:1b"

    # 1. Khởi chạy Ollama Core ngầm (Port 11436)
    ollama_process = subprocess.Popen(["ollama", "serve"], env=env)
    print("✅ Ollama Core đang lắng nghe tại cổng 11436.")
    time.sleep(2)

    # 2. Khởi chạy AI Proxy Guardrail Server (Port 11435)
    proxy_process = subprocess.Popen([sys.executable, "proxy_server.py"], env=env)
    print("✅ AI Guardrail Proxy Server khởi chạy trên cổng 11435.")
    time.sleep(2)

    # 3. Khởi chạy Streamlit Dashboard (Port 8501)
    print("✅ Đang mở Streamlit Dashboard trên cổng 8501...")
    try:
        subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py", "--server.port", "8501"], env=env)
    except KeyboardInterrupt:
        print("\n🛑 Đang dừng toàn bộ hệ thống...")
        proxy_process.terminate()
        ollama_process.terminate()

if __name__ == "__main__":
    run_system()