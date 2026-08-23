import json
import re
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
import httpx
import requests
import uvicorn

app = FastAPI(title="LLMVault AI Guardrail Proxy")

OLLAMA_BASE_URL = "http://127.0.0.1:11434"

# Danh sách quy tắc lọc an ninh cơ bản (Blacklist Regex)
DENY_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"reveal (your )?system prompt",
    r"reveal (your )?secret admin passkey",
    r"reveal internal admin api key",
    r"system override",
    r"bypass safety",
    r"do anything now",
    r"format c:",
    r"drop database",
    r"drop table",
    r"admin api key",
]


def check_guardrail(prompt: str) -> tuple[bool, str]:
    """Kiểm tra prompt qua bộ lọc Security Guardrail."""
    prompt_lower = prompt.lower()
    for pattern in DENY_PATTERNS:
        if re.search(pattern, prompt_lower):
            return True, f"Phát hiện hành vi vi phạm quy tắc an ninh: '{pattern}'"
    return False, ""


def generate_blocked_stream(reason_msg: str):
    """Hàm sinh luồng sự kiện (SSE Stream) cho Chatbox khi phát hiện tấn công."""
    chunk = {
        "id": "chatcmpl-blocked",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": "guardrail-proxy",
        "choices": [
            {
                "index": 0,
                "delta": {
                    "role": "assistant",
                    "content": f"🚨 [AI FIREWALL BLOCKED]: Yêu cầu bị từ chối. Lý do: {reason_msg}",
                },
                "finish_reason": "stop",
            }
        ],
    }
    yield f"data: {json.dumps(chunk)}\n\n"
    yield "data: [DONE]\n\n"


@app.post("/v1/chat/completions")
async def proxy_chat(request: Request):
    """Endpoint chuẩn OpenAI API (Cổng 11435) cho Chatbox & Module 1/2."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    messages = body.get("messages", [])
    is_stream = body.get("stream", False)

    # 1. Trích xuất Prompt từ Request
    user_prompt = ""
    for msg in messages:
        if isinstance(msg, dict) and msg.get("role") == "user":
            user_prompt += " " + str(msg.get("content", ""))

    # 2. Kiểm tra bộ luật Firewall Proxy (Layer 1)
    is_blocked, reason = check_guardrail(user_prompt)

    if is_blocked:
        if is_stream:
            return StreamingResponse(
                generate_blocked_stream(reason), media_type="text/event-stream"
            )
        else:
            return JSONResponse(
                status_code=403,
                content={
                    "blocked": True,
                    "reason": reason,
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": f"🚨 [AI FIREWALL BLOCKED]: Yêu cầu bị từ chối. Lý do: {reason}",
                            }
                        }
                    ],
                },
            )

    # 3. Nếu An toàn -> Đẩy tiếp tới Ollama API (Port 11434)
    target_url = f"{OLLAMA_BASE_URL}/v1/chat/completions"
    try:
        resp = requests.post(
            target_url, json=body, stream=is_stream, timeout=120
        )

        if is_stream:

            def stream_generator():
                for chunk in resp.iter_content(chunk_size=1024):
                    if chunk:
                        yield chunk

            return StreamingResponse(
                stream_generator(),
                media_type=resp.headers.get(
                    "content-type", "text/event-stream"
                ),
            )
        else:
            return JSONResponse(
                status_code=resp.status_code, content=resp.json()
            )

    except Exception as e:
        error_msg = (
            f"❌ Không thể kết nối tới Ollama Core (Port 11434): {str(e)}"
        )
        if is_stream:
            return StreamingResponse(
                generate_blocked_stream(error_msg),
                media_type="text/event-stream",
            )
        return JSONResponse(status_code=500, content={"detail": error_msg})


@app.post("/api/chat")
@app.post("/api/generate")
async def proxy_ollama_native(request: Request):
    """Endpoint chuẩn Ollama Native API hỗ trợ chuyển tiếp trực tiếp."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    prompt = body.get("prompt", "")
    if not prompt and "messages" in body:
        messages = body.get("messages", [])
        prompt = " ".join(
            [
                m.get("content", "")
                for m in messages
                if isinstance(m, dict) and m.get("role") == "user"
            ]
        )

    is_blocked, reason = check_guardrail(prompt)
    if is_blocked:
        return JSONResponse(
            status_code=403, content={"blocked": True, "reason": reason}
        )

    async with httpx.AsyncClient() as client:
        try:
            url = f"{OLLAMA_BASE_URL}{request.url.path}"
            response = await client.post(url, json=body, timeout=120.0)
            return JSONResponse(
                status_code=response.status_code, content=response.json()
            )
        except Exception as e:
            return JSONResponse(
                status_code=500,
                content={
                    "detail": f"Không thể kết nối tới Ollama Core (Port 11434): {str(e)}"
                },
            )


if __name__ == "__main__":
    print("🛡️ AI Proxy Guardrail Server đang chạy tại http://localhost:11435")
    uvicorn.run(app, host="0.0.0.0", port=11435)