@echo off
chcp 65001 >nul
title LLMVault Security Suite - Orchestrator
color 0B

echo ==============================================================================
echo               🚀 KHỞI ĐỘNG HỆ THỐNG AN NINH LLMVAULT (OWASP 2026)
echo ==============================================================================

:: 1. Đọc biến môi trường từ file .env (nếu có)
if exist .env (
    echo [*] Đang nạp cấu hình từ tệp .env...
    for /f "usebackq tokens=1* delims==" %%i in (`findstr /v "^#" .env ^| findstr /r "^[A-Za-z]"`) do (
        set "%%i=%%j"
    )
) else (
    echo [!] Không tìm thấy tệp .env, áp dụng cấu hình mặc định.
    set OLLAMA_PORT=11436
    set PROXY_PORT=11435
    set STREAMLIT_PORT=8501
    set OLLAMA_KEEP_ALIVE=-1
    set AI_JUDGE_MODEL=llama3.2:1b
)

:: 2. Khởi chạy Ollama Core ngầm
echo.
echo [1/3] Đang khởi chạy dịch vụ Ollama Core tại cổng %OLLAMA_PORT%...
set OLLAMA_HOST=127.0.0.1:%OLLAMA_PORT%
set OLLAMA_KEEP_ALIVE=%OLLAMA_KEEP_ALIVE%
start "Ollama Core Engine" /B ollama serve

:: Chờ kiểm tra kết nối cổng Ollama
:WAIT_OLLAMA
timeout /t 2 /nobreak >nul
netstat -ano | findstr /R /C:":%OLLAMA_PORT% .*LISTENING" >nul
if errorlevel 1 (
    echo     ... Đang đợi Ollama Core sẵn sàng ...
    goto WAIT_OLLAMA
)
echo [*] Ollama Core đã sẵn sàng hoạt động!

:: 3. Khởi chạy Tường lửa AI Proxy
echo.
echo [2/3] Đang khởi chạy Tường lửa AI Guardrail Proxy tại cổng %PROXY_PORT%...
start "AI Guardrail Proxy" /B python proxy_server.py

:: Chờ kiểm tra kết nối cổng Proxy
:WAIT_PROXY
timeout /t 1 /nobreak >nul
netstat -ano | findstr /R /C:":%PROXY_PORT% .*LISTENING" >nul
if errorlevel 1 (
    echo     ... Đang đợi AI Proxy thiết lập cổng ...
    goto WAIT_PROXY
)
echo [*] AI Guardrail Proxy đã sẵn sàng tiếp nhận request!

:: 4. Khởi chạy Dashboard Streamlit và Tự động mở trình duyệt
echo.
echo [3/3] Đang kích hoạt giao diện điều hành Streamlit tại cổng %STREAMLIT_PORT%...
echo ==============================================================================
echo [OK] Toàn bộ hệ thống đã hoạt động đồng bộ.
echo      - Web Dashboard : http://localhost:%STREAMLIT_PORT%
echo      - AI Proxy      : http://localhost:%PROXY_PORT%
echo      - Ollama Core   : http://localhost:%OLLAMA_PORT%
echo ==============================================================================

:: Tự động bật tab trên trình duyệt mặc định
start http://localhost:%STREAMLIT_PORT%

:: Khởi chạy máy chủ Streamlit
python -m streamlit run app.py --server.port %STREAMLIT_PORT% --server.address 0.0.0.0 --server.headless false

pause