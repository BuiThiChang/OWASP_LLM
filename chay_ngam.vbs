Set WshShell = CreateObject("WScript.Shell")

' 1. Chạy dịch vụ Ollama gốc ngầm tại cổng 11436
WshShell.Run "cmd /c set OLLAMA_HOST=127.0.0.1:11436 && ollama serve", 0, False

' 2. Chạy Proxy Tường lửa AI ngầm tại cổng 11434
WshShell.Run "cmd /c cd /d C:\Users\Chang\LLM-Security-Tester && python proxy_server.py", 0, False

' 3. Chạy Web Dashboard Streamlit (app.py) ngầm
WshShell.Run "cmd /c cd /d C:\Users\Chang\LLM-Security-Tester && streamlit run app.py", 0, False