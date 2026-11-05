"""
FILE: proxy_server.py
Mô tả: Tường lửa AI Guardrail Proxy (Cổng 11435).
- Tích hợp quét tệp/ảnh (Indirect Prompt Injection) qua /api/scan-file
- Đẩy mẫu payload độc hại vào Threat Intelligence DB
- Chặn lọc 10 nhóm OWASP 2026 (A01 -> A10) chuẩn hóa đồng nhất
- Chuẩn hóa đầu ra 3 trạng thái: BLOCKED | FAIL | PASS
- Hỗ trợ cả Streaming (SSE) và chuẩn OpenAI/Ollama, chống lỗi trắng khung chat
"""

import json
import asyncio
import requests
import uvicorn
from datetime import datetime

from fastapi import FastAPI, Request, File, UploadFile
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from db_manager import get_db_connection, save_result

# 1. IMPORT CSDL & THREAT INTEL
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

# 3. IMPORT ENGINE BẢO MẬT & HÀM CHUẨN HÓA DANH MỤC
from security_engine import (
    evaluate_owasp_top_10, 
    evaluate_full_cycle, 
    evaluate_with_llm_judge,
    normalize_to_owasp_2026
)

app = FastAPI(title="AI Security Guardrail Proxy - Unified Engine", version="2.6")

# BẬT CORS MIDDLEWARE
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
import os
REAL_OLLAMA_URL = os.getenv("OLLAMA_CORE_URL", "http://localhost:11436").rstrip("/")
SECRET = "OWASP-LLM-TEST-2026-7F3A9C"

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"📡 [PROXY CONNECTION]: {request.method} {request.url.path}")
    response = await call_next(request)
    return response

# HÀM FAKE SSE STREAMING CHO CHATBOX/STREAMLIT
async def fake_sse_stream(text_response: str, model_name: str):
    words = text_response.split(" ")
    for word in words:
        chunk = {
            "id": f"chatcmpl-{int(datetime.utcnow().timestamp())}",
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
        resp = requests.get(f"{REAL_OLLAMA_URL}/api/tags", timeout=500)
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
    """Bóc tách prompt từ cấu trúc body OpenAI / Ollama"""
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
# CHỨC NĂNG 1: QUÉT TỆP VÀ HÌNH ẢNH (INDIRECT PROMPT INJECTION)
# =============================================================================
@app.post("/api/scan-file")
async def scan_multimodal_file(file: UploadFile = File(...)):
    file_bytes = await file.read()
    filename = file.filename
    
    # BƯỚC 1: Bóc tách chữ từ ảnh/tệp
    extracted_text = extract_text_from_file(file_bytes, filename)
    
    if not extracted_text or not extracted_text.strip():
        return JSONResponse(status_code=400, content={
            "status": "FAIL",
            "reason": "Không thể trích xuất văn bản từ hình ảnh (Ảnh không có chữ hoặc Tesseract OCR chưa hoạt động).",
            "extracted_text_preview": ""
        })

    print(f"\n🔍 [OCR THÀNH CÔNG - {filename}]: Nội dung bóc tách được:\n'{extracted_text}'\n")

    # BƯỚC 2: Thẩm định an toàn
    eval_res = evaluate_owasp_top_10(extracted_text, SECRET)
    
    # BƯỚC 3: Xử lý theo chuẩn mã OWASP 2026 (A05: Injection)
    if eval_res.get("status") in ["BLOCKED", "FAIL"]:
        block_reason = eval_res.get("reason", "Phát hiện chỉ thị tấn công Indirect Prompt Injection ẩn trong ảnh.")
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

    # BƯỚC 4: Nếu chữ trong ảnh an toàn -> PASS
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
# CHỨC NĂNG 2: TƯỜNG LỬA KIỂM SOÁT VÀ ĐIỀU PHỐI CHAT PROMPT
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

    print(f"\n🔍 [PROXY KIỂM DUYỆT]: '{user_prompt}'")

    # BƯỚC 1: KIỂM TRA ĐẦU VÀO (CHỈ DÙNG RULE ENGINE NHANH, KHÔNG CHẶN NHẦM)
    firewall_eval = evaluate_owasp_top_10(user_prompt, SECRET)
    is_violation = False
    block_reason = ""
    raw_category = "A05:2026 - Injection"
    raw_test_id = "A05"

    if firewall_eval and firewall_eval.get("status") in ["BLOCKED", "FAIL"]:
        is_violation = True
        block_reason = firewall_eval.get("reason", "Phát hiện chỉ thị nguy hiểm.")
        raw_category = firewall_eval.get("category", raw_category)
        raw_test_id = firewall_eval.get("test_id", "A05")

    target_endpoint = request.url.path
    current_time_str = datetime.utcnow().isoformat() + "Z"

    # BƯỚC 2: XỬ LÝ VI PHẠM (TRẠNG THÁI: BLOCKED)
    if is_violation:
        clean_id, clean_category = normalize_to_owasp_2026(raw_test_id, raw_category)
        
        print(f"🚨 [BLOCKED - {clean_category}]: {block_reason}")
        blocked_message = f"🚨 **[BLOCKED BY SECURITY FIREWALL]**\n\n❌ **Nhóm lỗi:** {clean_category}\n🔒 **Lý do:** {block_reason}"

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

        if "/v1/" in target_endpoint:
            return JSONResponse(status_code=200, content={
                "id": "chatcmpl-blocked",
                "object": "chat.completion",
                "created": int(datetime.utcnow().timestamp()),
                "model": model_name,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": blocked_message},
                    "finish_reason": "stop"
                }]
            })
        elif "/api/chat" in target_endpoint:
            return JSONResponse(status_code=200, content={
                "model": model_name,
                "created_at": current_time_str,
                "message": {"role": "assistant", "content": blocked_message},
                "done": True
            })
        else:
            return JSONResponse(status_code=200, content={
                "model": model_name,
                "created_at": current_time_str,
                "response": blocked_message,
                "done": True
            })

    # BƯỚC 3: AN TOÀN -> CHUYỂN TIẾP TỚI OLLAMA THẬT (CỔNG 11436)
    print("✅ [SAFE INPUT]: Chuyển tiếp tới Ollama Core (11436)...")
    try:
        if "/v1/" in target_endpoint:
            body["stream"] = False

        resp = requests.post(
            f"{REAL_OLLAMA_URL}{target_endpoint}", 
            json=body, 
            timeout=120, 
            stream=is_stream
        )

        if resp.status_code == 200:
            if is_stream:
                return StreamingResponse(
                    resp.iter_content(chunk_size=1024),
                    media_type=resp.headers.get("content-type", "text/event-stream")
                )
            
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

            # Thẩm định đầu ra toàn chu trình (KẾT HỢP CẢ AI JUDGE)
            verdict, audit_reason = evaluate_full_cycle(
                category_code="SAFE",
                prompt=user_prompt,
                response_text=ai_response_text,
                status_code=200,
                secret=SECRET,
                model_name=model_name
            )

            # Ghi log chuẩn trạng thái: PASS | FAIL | ERROR
            try:
                save_result(
                    model=model_name,
                    test_id={"PASS": "SAFE", "FAIL": "A05"}.get(verdict, "ERROR"),
                    category={"PASS": "An toàn / Nghiệp vụ Hợp lệ",
                              "FAIL": "A05:2026 - Injection"}.get(verdict, "Lỗi hệ thống / AI Judge"),
                    name="Truy vấn Chatbot Trực tiếp",
                    prompt=user_prompt,
                    response=ai_response_text,
                    status=verdict,
                    reason=audit_reason
                )
            except Exception as db_err:
                print(f"⚠️ Lỗi ghi CSDL: {db_err}")

            if "/v1/" in target_endpoint:
                formatted_resp = {
                    "id": "chatcmpl-proxy",
                    "object": "chat.completion",
                    "created": int(datetime.utcnow().timestamp()),
                    "model": model_name,
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": ai_response_text},
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}
                }
                return JSONResponse(status_code=200, content=formatted_resp)

            return JSONResponse(status_code=200, content=resp_data)

        # Ollama trả về lỗi (khác 200): báo lỗi rõ ràng thay vì trả về null
        print(f"❌ [OLLAMA BÁO LỖI HTTP {resp.status_code}]: {resp.text[:200]}")
        return JSONResponse(status_code=502, content={"error": f"Ollama Core trả về lỗi HTTP {resp.status_code}: {resp.text[:500]}"})

    except Exception as e:
        print(f"❌ [LỖI KẾT NỐI BACKEND]: {e}")
        return JSONResponse(status_code=500, content={"error": f"Internal Proxy Error: {str(e)}"})

# CATCH-ALL FORWARDING
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
    target_port = 11435
    print(f"🛡️ AI Security Guardrail Proxy đang hoạt động tại cổng http://localhost:{target_port}")
    uvicorn.run(app, host="0.0.0.0", port=target_port)