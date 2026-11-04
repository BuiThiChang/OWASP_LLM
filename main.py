import subprocess
import time
import sys

def run_system():
    print("🚀 Đang khởi động LLMVault Security Suite...")
    
    # 1. Chạy AI Proxy Guardrail Server (Port 11435)
    proxy_process = subprocess.Popen([sys.executable, "proxy_server.py"])
    print("✅ AI Guardrail Proxy Server khởi chạy trên cổng 11435.")
    
    time.sleep(2)
    
    # 2. Chạy Streamlit Dashboard (Port 8501) chuẩn qua sys.executable
    print("✅ Đang mở Streamlit Dashboard...")
    try:
        subprocess.run([sys.executable, "-m", "streamlit", "run", "app.py"])
    except KeyboardInterrupt:
        print("\n🛑 Đang dừng hệ thống...")
        proxy_process.terminate()

if __name__ == "__main__":
    run_system()