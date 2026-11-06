Set WshShell = CreateObject("WScript.Shell")

' 1. Khởi chạy Ollama ngầm ở cổng 11436 + Giữ mô hình thường trực trên RAM/VRAM
WshShell.Run "cmd /c set OLLAMA_HOST=127.0.0.1:11436 && set OLLAMA_KEEP_ALIVE=-1 && ollama serve", 0, False

' 2. Khởi chạy Guardrail Proxy ngầm (Cổng 11435) cố định Model Judge nhẹ chuyên biệt llama3.2:1b
WshShell.Run "cmd /c cd /d C:\Users\Chang\LLM-Security-Tester && set AI_JUDGE_MODEL=llama3.2:1b && python proxy_server.py", 0, False

' 3. Khởi chạy Streamlit Dashboard ngầm (Cổng 8501)
WshShell.Run "cmd /c cd /d C:\Users\Chang\LLM-Security-Tester && streamlit run app.py --server.address 0.0.0.0 --server.port 8501", 0, False