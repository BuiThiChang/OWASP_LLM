import json
import asyncio
import requests
import uvicorn
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

# Import hàm kiểm thử từ security_engine và CSDL từ pages.db_manager
from security_engine import evaluate_owasp_top_10
try:
    from pages.db_manager import save_result
except ImportError:
    def save_result(*args, **kwargs): pass

app = FastAPI(title="LLM Security Guardrail Proxy")

# 1. BẬT CORS MIDDLEWARE
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REAL_OLLAMA_URL = "http://localhost:11436"
SECRET = "OWASP-LLM-TEST-2026-7F3A9C"

# Hàm giả lập SSE Stream để Chatbox AI gõ chữ mượt mà
async def fake_sse_stream(text_response: str, model_name: str):
    words = text_response.split(" ")
    for word in words:
        chunk = {
            "id": f"chatcmpl-{int(datetime.now().timestamp())}",
            "object": "chat.completion.chunk",
            "model": model_name,
            "choices": [{"index": 0, "delta": {"content": word + " "}, "finish_reason": None}]
        }
        yield f"data: {json.dumps(chunk)}\n\n"
        await asyncio.sleep(0.02)
    yield "data: [DONE]\n\n"

@app.get("/v1/models")
async def get_models():
    try:
        resp = requests.get(f"{REAL_OLLAMA_URL}/api/tags", timeout=5)
        if resp.status_code == 200:
            models_data = resp.json().get("models", [])
            data = [{"id": m["name"], "object": "model", "owned_by": "ollama"} for m in models_data]
            return {"object": "list", "data": data}
    except Exception:
        pass
    return {"object": "list", "data": [{"id": "llama3.2:3b", "object": "model", "owned_by": "ollama"}]}

@app.api_route("/api/generate", methods=["GET", "POST", "OPTIONS"])
@app.api_route("/api/chat", methods=["GET", "POST", "OPTIONS"])
@app.api_route("/v1/chat/completions", methods=["GET", "POST", "OPTIONS"])
async def security_proxy(request: Request):
    if request.method in ["GET", "OPTIONS"]:
        return JSONResponse(status_code=200, content={"status": "ok", "message": "Proxy Ready"})

    try:
        body = await request.json()
    except Exception:
        body = {}

    model_name = body.get("model", "llama3.2:3b")
    is_stream = body.get("stream", True)

    # Bóc tách prompt từ request
    user_prompt = ""
    if "prompt" in body:
        raw_p = body["prompt"]
        if isinstance(raw_p, list):
            user_prompt = " ".join([item.get("text", "") for item in raw_p if isinstance(item, dict)])
        else:
            user_prompt = str(raw_p)
    elif "messages" in body and len(body["messages"]) > 0:
        last_msg = body["messages"][-1].get("content", "")
        if isinstance(last_msg, list):
            user_prompt = " ".join([item.get("text", "") for item in last_msg if isinstance(item, dict)])
        else:
            user_prompt = str(last_msg)

    print(f"\n🔍 [PROXY KIỂM DUYỆT]: '{user_prompt}'")

    # BƯỚC 1: ĐÁNH GIÁ BẢO MẬT OWASP TOP 10
    eval_result = evaluate_owasp_top_10(user_prompt, SECRET)

    # BƯỚC 2: NẾU VI PHẠM -> CHẶN ĐỨNG VÀ GHI LOG
    if eval_result["status"] == "FAIL":
        category_name = eval_result["category"]
        block_reason = eval_result["reason"]
        print(f"🚨 [BLOCKED - {category_name}]: {block_reason}")
        
        try:
            save_result(
                model=model_name,
                test_id="PROXY-BLOCKED",
                category=category_name,
                name="Live Chat Attack Blocked",
                prompt=user_prompt,
                response="[BLOCKED BY SECURITY FIREWALL]",
                status="FAIL",
                reason=block_reason
            )
        except Exception:
            pass

        blocked_message = f"🚨 **[TƯỜNG LỬA AI NGĂN CHẶN]**\n\n❌ **Nhóm vi phạm:** {category_name}\n🔒 **Lý do:** {block_reason}"
        
        if is_stream:
            return StreamingResponse(fake_sse_stream(blocked_message, model_name), media_type="text/event-stream")
        
        return JSONResponse({"choices": [{"message": {"role": "assistant", "content": blocked_message}}]})

    # BƯỚC 3: AN TOÀN -> CHUYỂN TIẾP TỚI OLLAMA THẬT (PORT 11436)
    print("✅ [PASSED]: Chuyển tiếp tới Ollama...")
    try:
        resp = requests.post(f"{REAL_OLLAMA_URL}{request.url.path}", json=body, stream=is_stream)
        if is_stream:
            return StreamingResponse(resp.iter_content(chunk_size=1024), media_type=resp.headers.get("content-type", "text/event-stream"))
        return JSONResponse(status_code=resp.status_code, content=resp.json())
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def catch_all_proxy(request: Request, path: str):
    url = f"{REAL_OLLAMA_URL}/{path}"
    try:
        req_content = await request.body()
        resp = requests.request(
            method=request.method,
            url=url,
            headers={k: v for k, v in request.headers.items() if k.lower() != 'host'},
            data=req_content,
            allow_redirects=False
        )
        return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=11435)