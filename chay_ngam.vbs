Set WshShell = CreateObject("WScript.Shell")
' Khởi chạy Ollama ngầm ở cổng 11436
WshShell.Run "cmd /c set OLLAMA_HOST=127.0.0.1:11436 && ollama serve", 0, False
' Khởi chạy Guardrail Proxy ngầm
WshShell.Run "cmd /c cd /d C:\Users\Chang\LLM-Security-Tester && python proxy_server.py", 0, False
' Khởi chạy Streamlit Dashboard ngầm cho phép truy cập từ LAN
WshShell.Run "cmd /c cd /d C:\Users\Chang\LLM-Security-Tester && streamlit run app.py --server.address 0.0.0.0 --server.port 8501", 0, False