"""
FILE: proxy_server.py
Mô tả: Tường lửa AI Guardrail Proxy (Cổng 11435) - Phiên bản Tối ưu hóa Hiệu năng & Bất đồng bộ.
- Chuyển đổi toàn diện sang httpx.AsyncClient (Non-blocking I/O)
- Cắt giảm độ trễ đầu vào (< 50ms) bằng In-memory LRU Cache & Short-circuiting
- Hỗ trợ Streaming SSE 2 chiều trực tiếp từ Ollama Core
- Đồng bộ chuẩn hóa dữ liệu bảo mật OWASP Top 10 (2026)
- Tích hợp Judge nhẹ llama3.2:1b cho tầng hậu kiểm
"""

import json
import asyncio
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from collections import OrderedDict

import httpx
import uvicorn
from fastapi import FastAPI, Request, File, UploadFile
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware


# 1. IMPORT CSDL & THREAT INTEL
from db_manager import save_result
try:
    from db_manager import save_or_update_threat_intel
except ImportError:
    def save_or_update_threat_intel(*args, **kwargs): pass

# 2. IMPORT BỘ BÓC TÁCH FILE
try:
    from file_processor import extract_text_from_file
except ImportError:
    def extract_text_from_file(file_bytes, filename):
        return file_bytes.decode("utf-8", errors="ignore")

# 3. IMPORT ENGINE BẢO MẬT & HÀM CHUẨN HÓA
from security_engine import (
    evaluate_owasp_top_10, 
    evaluate_full_cycle, 
    normalize_to_owasp_2026,
    DEFAULT_JUDGE_MODEL,
    COMPILED_CCCD,
    COMPILED_POLICE_SECRETS
)
from threat_intel_engine import inspect_threat_multitier

app = FastAPI(title="AI Security Guardrail Proxy - High Performance", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


import os
from dotenv import load_dotenv

load_dotenv()

REAL_OLLAMA_URL = os.getenv("OLLAMA_CORE_URL", "http://127.0.0.1:11436").rstrip(
    "/"
)
SECRET = os.getenv("SYSTEM_SECRET_KEY", "OWASP-LLM-TEST-2026-7F3A9C")
PROXY_PORT = int(os.getenv("PROXY_PORT", "11435"))
PROXY_HOST = os.getenv("PROXY_HOST", "0.0.0.0")


# -----------------------------------------------------------------------------
# BỘ NHỚ ĐỆM IN-MEMORY CACHE ĐẦU VÀO
# -----------------------------------------------------------------------------
class SimpleLRUCache:
    def __init__(self, capacity: int = 500):
        self.cache = OrderedDict()
        self.capacity = capacity

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if key not in self.cache:
            return None
        self.cache.move_to_end(key)
        return self.cache[key]

    def set(self, key: str, value: Dict[str, Any]):
        self.cache[key] = value
        self.cache.move_to_end(key)
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)

INPUT_CACHE = SimpleLRUCache(capacity=1000)

async_http_client: Optional[httpx.AsyncClient] = None

@app.on_event("startup")
async def startup_event():
    global async_http_client
    async_http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(120.0, connect=10.0),
        limits=httpx.Limits(max_keepalive_connections=50, max_connections=200)
    )

@app.on_event("shutdown")
async def shutdown_event():
    global async_http_client
    if async_http_client:
        await async_http_client.aclose()

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"📡 [PROXY ASYNC]: {request.method} {request.url.path}")
    return await call_next(request)

async def fake_sse_stream(text_response: str, model_name: str):
    words = text_response.split(" ")
    for word in words:
        chunk = {
            "id": f"chatcmpl-{int(datetime.now(timezone.utc).timestamp())}",
            "object": "chat.completion.chunk",
            "model": model_name,
            "choices": [{"index": 0, "delta": {"content": word + " "}, "finish_reason": None}]
        }
        yield f"data: {json.dumps(chunk)}\n\n"
        await asyncio.sleep(0.01)
    yield "data: [DONE]\n\n"

@app.get("/v1/models")
async def get_models():
    try:
        resp = await async_http_client.get(f"{REAL_OLLAMA_URL}/api/tags", timeout=5.0)
        if resp.status_code == 200:
            models_data = resp.json().get("models", [])
            data = [{"id": m["name"], "object": "model", "owned_by": "ollama"} for m in models_data]
            return {"object": "list", "data": data}
    except Exception:
        pass
    return {"object": "list", "data": [{"id": "llama3.2:3b", "object": "model", "owned_by": "ollama"}]}

@app.get("/api/version")
async def get_version():
    return {"version": "0.3.14"}

@app.api_route("/api/me", methods=["GET", "POST"])
async def fake_me():
    return JSONResponse(status_code=200, content={"user": "local_user", "status": "authenticated"})

def extract_prompt_from_body(body: dict) -> str:
    if "prompt" in body:
        raw_p = body["prompt"]
        if isinstance(raw_p, list):
            return " ".join([item.get("text", "") for item in raw_p if isinstance(item, dict)])
        return str(raw_p)
    elif "messages" in body and len(body["messages"]) > 0:
        last_msg = body["messages"][-1].get("content", "")
        if isinstance(last_msg, list):
            return " ".join([item.get("text", "") for item in last_msg if isinstance(item, dict)])
        return str(last_msg)
    return ""

# =============================================================================
# CHỨC NĂNG 1: QUÉT TỆP VÀ HÌNH ẢNH (ASYNC)
# =============================================================================
@app.post("/api/scan-file")
async def scan_multimodal_file(file: UploadFile = File(...)):
    file_bytes = await file.read()
    filename = file.filename
    
    extracted_text = extract_text_from_file(file_bytes, filename)
    if not extracted_text or not extracted_text.strip():
        return JSONResponse(status_code=400, content={
            "status": "FAIL",
            "reason": "Không thể trích xuất văn bản từ hình ảnh/tệp.",
            "extracted_text_preview": ""
        })

    eval_res = evaluate_owasp_top_10(extracted_text, SECRET)
    
    if eval_res.get("status") in ["BLOCKED", "FAIL"]:
        block_reason = eval_res.get("reason", "Phát hiện chỉ thị độc hại ẩn trong tài liệu/ảnh.")
        raw_cat = eval_res.get("category", "A05:2026 - Injection")
        clean_id, clean_cat = normalize_to_owasp_2026("A05", raw_cat)
        
        save_result(
            model="multimodal-ocr",
            test_id=clean_id,
            category=clean_cat,
            name=f"Quét tệp: {filename}",
            prompt=extracted_text[:400],
            response="[BLOCKED BY SECURITY FIREWALL]",
            status="BLOCKED",
            reason=block_reason
        )
        return JSONResponse(status_code=400, content={
            "status": "BLOCKED",
            "filename": filename,
            "reason": block_reason,
            "extracted_text_preview": extracted_text
        })

    save_result(
        model="multimodal-ocr",
        test_id="SAFE",
        category="An toàn / Nghiệp vụ Hợp lệ",
        name=f"Quét tệp: {filename}",
        prompt=extracted_text[:400],
        response="[CLEAN FILE]",
        status="PASS",
        reason="Nội dung ảnh an toàn, không chứa chỉ thị độc hại."
    )
    return JSONResponse(status_code=200, content={
        "status": "PASS",
        "filename": filename,
        "message": "Nội dung văn bản trong ảnh an toàn.",
        "extracted_text": extracted_text
    })

# =============================================================================
# CHỨC NĂNG 2: TƯỜNG LỬA KIỂM SOÁT VÀ ĐIỀU PHỐI (NON-BLOCKING STREAMING PROXY)
# =============================================================================
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
    is_stream = body.get("stream", False)
    user_prompt = extract_prompt_from_body(body)

    # 1. Kiểm tra qua Hệ thống Phòng thủ Đa tầng (Multi-tier Defense Pipeline)
    cached_eval = INPUT_CACHE.get(user_prompt)
    if cached_eval:
        firewall_eval = cached_eval
    else:
        firewall_eval = inspect_threat_multitier(user_prompt, SECRET, use_guard_model=False)
        INPUT_CACHE.set(user_prompt, firewall_eval)

    # 2. Ngắt sớm nếu vi phạm
    if firewall_eval and firewall_eval.get("status") in ["BLOCKED", "FAIL"]:
        block_reason = firewall_eval.get("reason", "Phát hiện chỉ thị nguy hiểm.")
        clean_category = firewall_eval.get("category_name", "A05:2026 - Injection")
        clean_id = firewall_eval.get("category_code", "A05")
        layer_triggered = firewall_eval.get("layer_triggered", "Tường lửa AI Proxy")
        
        print(f"🚨 [{layer_triggered} - {clean_category}]: {block_reason}")
        blocked_message = f"🚨 **[BLOCKED BY SECURITY FIREWALL]**\n\n🛡️ **Lớp đánh chặn:** {layer_triggered}\n❌ **Nhóm lỗi:** {clean_category}\n🔒 **Lý do:** {block_reason}"

        try:
            save_result(
                model=model_name,
                test_id=clean_id,
                category=clean_category,
                name="AI Guardrail Proxy",
                prompt=user_prompt,
                response="[BLOCKED BY SECURITY FIREWALL]",
                status="BLOCKED",
                reason=block_reason
            )
            save_or_update_threat_intel(
                attack_payload=user_prompt,
                vector_type=clean_category,
                owasp_category=clean_category,
                detected_source="BLUE_TEAM",
                detector_rule="AI Guardrail Proxy Firewall",
                tactics_desc=f"Truy vấn bị chặn tại Tường lửa. Lý do: {block_reason}"
            )
        except Exception as e:
            print(f"⚠️ Lỗi ghi CSDL: {e}")

        if is_stream:
            return StreamingResponse(
                fake_sse_stream(blocked_message, model_name),
                media_type="text/event-stream"
            )

        target_endpoint = request.url.path
        if "/v1/" in target_endpoint:
            return JSONResponse(status_code=200, content={
                "id": "chatcmpl-blocked",
                "object": "chat.completion",
                "created": int(datetime.now(timezone.utc).timestamp()),
                "model": model_name,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": blocked_message},
                    "finish_reason": "stop"
                }]
            })
        return JSONResponse(status_code=200, content={"message": {"role": "assistant", "content": blocked_message}, "done": True})

    # 3. Chuyển tiếp tới Ollama Core
    target_endpoint = request.url.path
    backend_url = f"{REAL_OLLAMA_URL}{target_endpoint}"

    try:
        if is_stream:
            req = async_http_client.build_request("POST", backend_url, json=body)
            backend_resp = await async_http_client.send(req, stream=True)

            async def stream_generator():
                try:
                    async for chunk in backend_resp.aiter_bytes():
                        yield chunk
                finally:
                    await backend_resp.aclose()

            return StreamingResponse(
                stream_generator(),
                status_code=backend_resp.status_code,
                media_type=backend_resp.headers.get("content-type", "text/event-stream")
            )

        resp = await async_http_client.post(backend_url, json=body)
        
        if resp.status_code == 200:
            resp_data = resp.json()
            ai_response_text = ""
            if isinstance(resp_data, dict):
                try:
                    ai_response_text = resp_data["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError):
                    pass
                if not ai_response_text and "message" in resp_data:
                    msg = resp_data["message"]
                    ai_response_text = msg.get("content", "") if isinstance(msg, dict) else str(msg)
                if not ai_response_text and "response" in resp_data:
                    ai_response_text = str(resp_data["response"])

            # Thẩm định an ninh đầu ra bằng Judge nhẹ llama3.2:1b & DLP
            verdict, audit_reason = evaluate_full_cycle(
                category_code="SAFE",
                prompt=user_prompt,
                response_text=ai_response_text,
                status_code=200,
                secret=SECRET,
                model_name=DEFAULT_JUDGE_MODEL
            )

            is_leak = (verdict == "FAIL" or COMPILED_CCCD.search(ai_response_text) or COMPILED_POLICE_SECRETS.search(ai_response_text))

            if is_leak:
                dlp_reason = audit_reason if verdict == "FAIL" else "Phát hiện rò rỉ dữ liệu cá nhân (Số CCCD 12 chữ số) trong phản hồi đầu ra."
                blocked_message = f"🚨 **[BLOCKED BY SECURITY FIREWALL - OUTPUT DLP]**\n\n❌ **Nhóm lỗi:** A01:2026 - Broken Access Control & SSRF (DLP)\n🔒 **Lý do:** {dlp_reason}"
                print(f"🚨 [OUTPUT DLP BLOCKED]: {dlp_reason}")

                try:
                    save_result(
                        model=model_name,
                        test_id="A01",
                        category="A01:2026 - Broken Access Control & SSRF",
                        name="AI Guardrail Proxy - Output DLP",
                        prompt=user_prompt,
                        response="[BLOCKED BY SECURITY FIREWALL - OUTPUT DLP]",
                        status="BLOCKED",
                        reason=dlp_reason
                    )
                except Exception as db_err:
                    print(f"⚠️ Lỗi ghi CSDL DLP: {db_err}")

                if "/v1/" in target_endpoint:
                    return JSONResponse(status_code=200, content={
                        "id": "chatcmpl-dlp-blocked",
                        "object": "chat.completion",
                        "created": int(datetime.now(timezone.utc).timestamp()),
                        "model": model_name,
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": blocked_message},
                            "finish_reason": "stop"
                        }]
                    })
                return JSONResponse(status_code=200, content={"message": {"role": "assistant", "content": blocked_message}, "done": True})

            try:
                save_result(
                    model=model_name,
                    test_id="SAFE",
                    category="An toàn / Nghiệp vụ Hợp lệ",
                    name="Truy vấn Chatbot Trực tiếp",
                    prompt=user_prompt,
                    response=ai_response_text,
                    status=verdict,
                    reason=audit_reason
                )
            except Exception as db_err:
                print(f"⚠️ Lỗi ghi CSDL: {db_err}")

            return JSONResponse(status_code=200, content=resp_data)

        return JSONResponse(status_code=resp.status_code, content=resp.json())

    except Exception as e:
        print(f"❌ [LỖI KẾT NỐI BACKEND]: {e}")
        return JSONResponse(status_code=500, content={"error": f"Internal Proxy Error: {str(e)}"})

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def catch_all_proxy(request: Request, path: str):
    url = f"{REAL_OLLAMA_URL}/{path}"
    try:
        req_content = await request.body()
        resp = await async_http_client.request(
            method=request.method,
            url=url,
            headers={k: v for k, v in request.headers.items() if k.lower() != 'host'},
            content=req_content
        )
        return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

if __name__ == "__main__":
    uvicorn.run(app, host=PROXY_HOST, port=PROXY_PORT)
    