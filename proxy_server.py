import json
import asyncio
import requests
import uvicorn
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from db_manager import save_result, save_or_update_threat_intel  # Thêm save_or_update_threat_intel
from security_engine import evaluate_owasp_top_10
from db_manager import save_result


app = FastAPI(title="LLM Security Guardrail Proxy")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REAL_OLLAMA_URL = "http://localhost:11436"
SECRET = "OWASP-LLM-TEST-2026-7F3A9C"

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

    # BƯỚC 2: NẾU VI PHẠM -> CHẶN ĐỨNG VÀ GHI LOG (TRẠNG THÁI: BLOCKED)
    if eval_result.get("status") in ["FAIL", "BLOCKED"]:
        category_name = eval_result.get("category", "Security Violation")
        block_reason = eval_result.get("reason", "Phát hiện câu lệnh vi phạm quy tắc an toàn.")
        print(f"🚨 [BLOCKED - {category_name}]: {block_reason}")
        
        try:
            # Ghi Log audit thông thường
            save_result(
                model=model_name,
                test_id="PROXY-BLOCKED",
                category=category_name,
                name="AI Guardrail Proxy",
                prompt=user_prompt,
                response="[BLOCKED BY SECURITY FIREWALL]",
                status="BLOCKED",
                reason=block_reason
            )
            
            # 🌟 [BỔ SUNG BƯỚC 3]: Đẩy mẫu độc hại bị Blue Team chặn vào Threat Intelligence DB
            save_or_update_threat_intel(
                attack_payload=user_prompt,
                vector_type=category_name,
                owasp_category=category_name,
                detected_source="BLUE_TEAM",
                detector_rule="AI Guardrail Proxy Firewall",
                tactics_desc=f"Truy vấn bị chặn trực tiếp tại Tường lửa. Lý do: {block_reason}"
            )
        except Exception as e:
            print(f"⚠️ Lỗi ghi PostgreSQL Log: {e}")

    # BƯỚC 3: AN TOÀN -> CHUYỂN TIẾP TỚI OLLAMA THẬT (PORT 11436) (TRẠNG THÁI: SAFE / ERROR)
    print("✅ [PASSED]: Chuyển tiếp tới Ollama...")
    try:
        resp = requests.post(f"{REAL_OLLAMA_URL}{request.url.path}", json=body, stream=is_stream)
        
        try:
            save_result(
                model=model_name,
                test_id="PROXY-PASSED",
                category="General / Pass",
                name="AI Guardrail Proxy",
                prompt=user_prompt,
                response="[FORWARDED TO OLLAMA]",
                status="SAFE",
                reason="Prompt hợp lệ, đã chuyển tiếp tới Ollama xử lý."
            )
        except Exception as e:
            print(f"⚠️ Lỗi ghi PostgreSQL Log: {e}")

        if is_stream:
            return StreamingResponse(resp.iter_content(chunk_size=1024), media_type=resp.headers.get("content-type", "text/event-stream"))
        return JSONResponse(status_code=resp.status_code, content=resp.json())

    except Exception as e:
        try:
            save_result(
                model=model_name,
                test_id="PROXY-ERROR",
                category="System Error",
                name="AI Guardrail Proxy",
                prompt=user_prompt,
                response=f"[SYSTEM ERROR]: {str(e)}",
                status="ERROR",
                reason=f"Lỗi kết nối Backend Ollama: {str(e)}"
            )
        except Exception:
            pass
        return JSONResponse(status_code=500, content={"error": f"Internal Proxy Error: {str(e)}"})

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

# proxy_server.py
from fastapi import FastAPI, Request, File, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
import requests
import uvicorn

# Import các hàm kiểm thử, CSDL và mô-đun bóc tách file
from security_engine import evaluate_owasp_top_10, evaluate_with_llm_judge
from db_manager import save_result
from file_processor import extract_text_from_file

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

# -------------------------------------------------------------
# ENDPOINT MỚI: QUÉT VÀ KIỂM DUYỆT FILE / ẢNH CHỨNG CỨ
# -------------------------------------------------------------
@app.post("/api/scan-file")
async def scan_multimodal_file(file: UploadFile = File(...)):
    """
    Endpoint tiếp nhận file (PDF, DOCX, TXT, PNG, JPG), trích xuất văn bản
    và kiểm tra Indirect/Visual Prompt Injection qua AI Security Proxy.
    """
    file_bytes = await file.read()
    filename = file.filename
    
    # BƯỚC 1: Tiền xử lý dữ liệu - Bóc tách Text/OCR từ File hoặc Ảnh
    extracted_text = extract_text_from_file(file_bytes, filename)
    
    if not extracted_text:
        return JSONResponse(status_code=400, content={
            "status": "ERROR",
            "message": "Không thể trích xuất văn bản từ file hoặc file rỗng."
        })

    print(f"\n🔍 [FILE SCANNED - {filename}]: Đã trích xuất {len(extracted_text)} ký tự.")

    # BƯỚC 2: Kiểm tra an toàn Prompt Injection đối với nội dung bóc tách
    rule_eval = evaluate_owasp_top_10(extracted_text, SECRET)
    
    is_violation = False
    block_reason = ""

    if rule_eval and rule_eval["status"] == "FAIL":
        is_violation = True
        block_reason = f"[Indirect Attack File] {rule_eval['reason']}"
    else:
        judge_eval = evaluate_with_llm_judge("llama3.2:3b", extracted_text, "[File/Image Content Assessment]")
        if judge_eval and judge_eval.get("status") == "FAIL":
            is_violation = True
            block_reason = f"[Indirect Attack File] {judge_eval.get('reason', 'Phát hiện câu lệnh độc hại ẩn trong tài liệu/hình ảnh.')}"

    # BƯỚC 3: Ghi nhận Log & Trả về kết quả
    if is_violation:
        print(f"🚨 [FILE BLOCKED]: Phát hiện mã độc/chỉ thị ẩn trong file {filename}!")
        save_result(
            model="multimodal-parser",
            test_id="FILE-BLOCKED",
            category="Indirect Prompt Injection",
            name=f"File Scan: {filename}",
            prompt=extracted_text[:500] + "...",
            response="[BLOCKED BY SECURITY FIREWALL]",
            status="FAIL",
            reason=block_reason
        )
        return JSONResponse(status_code=400, content={
            "status": "BLOCKED",
            "filename": filename,
            "reason": block_reason,
            "extracted_text_preview": extracted_text[:200]
        })

    # Nếu An toàn
    save_result(
        model="multimodal-parser",
        test_id="FILE-PASSED",
        category="Indirect Prompt Injection",
        name=f"File Scan: {filename}",
        prompt=extracted_text[:500] + "...",
        response="[CLEAN FILE]",
        status="PASS",
        reason="Nội dung tài liệu/hình ảnh an toàn."
    )

    return JSONResponse(status_code=200, content={
        "status": "PASSED",
        "filename": filename,
        "message": "Tài liệu/Hình ảnh an toàn, không chứa chỉ thị độc hại.",
        "extracted_text": extracted_text
    })

# -------------------------------------------------------------
# ROUTE CỐT LÕI: CHẶN VÀ KIỂM TRA CHAT PROMPT THUẦN
# -------------------------------------------------------------
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

    print(f"\n🔍 [PROXY RECEIVED]: '{user_prompt}'")

    rule_eval = evaluate_owasp_top_10(user_prompt, SECRET)
    is_violation = False
    block_reason = ""

    if rule_eval and rule_eval["status"] == "FAIL":
        is_violation = True
        block_reason = rule_eval["reason"]
    else:
        judge_eval = evaluate_with_llm_judge(model_name, user_prompt, "[User Input Assessment]")
        if judge_eval and judge_eval.get("status") == "FAIL":
            is_violation = True
            block_reason = judge_eval.get("reason", "Phát hiện hành vi tấn công Prompt Injection.")

    if is_violation:
        print(f"🚨 [BLOCKED]: Vi phạm an toàn! Lý do: {block_reason}")
        save_result(model_name, "OLLAMA-BLOCKED", "Ollama Live Chat", "Blocked User Input", user_prompt, "[BLOCKED BY SECURITY FIREWALL]", "FAIL", block_reason)
        blocked_message = f"🚨 **[CẢNH BÁO BẢO MẬT]**: Yêu cầu của bạn đã bị Tường lửa AI ngăn chặn!\n\n❌ **Lý do:** {block_reason}\n🛡️ *Hệ thống đã ghi nhận sự cố này vào nhật ký kiểm toán.*"
        
        if "/v1/" in request.url.path:
            return JSONResponse({"id": "chatcmpl-blocked", "object": "chat.completion", "created": 1700000000, "model": model_name, "choices": [{"index": 0, "message": {"role": "assistant", "content": blocked_message}, "finish_reason": "stop"}]})
        return JSONResponse({"model": model_name, "response": blocked_message, "done": True})

    print("✅ [PASSED]: Gửi tới Ollama 11436...")
    try:
        target_endpoint = request.url.path
        body["stream"] = False
        response = requests.post(f"{REAL_OLLAMA_URL}{target_endpoint}", json=body, timeout=120)
        
        if response.status_code == 200:
            resp_data = response.json()
            ai_response_text = ""
            if "choices" in resp_data and len(resp_data["choices"]) > 0:
                ai_response_text = resp_data["choices"][0].get("message", {}).get("content", "")
            elif "response" in resp_data:
                ai_response_text = resp_data.get("response", "")

            save_result(model_name, "OLLAMA-PASS", "Ollama Live Chat", "Allowed User Input", user_prompt, ai_response_text, "PASS", "Prompt đáp ứng tiêu chuẩn an toàn.")

            if "/v1/" in target_endpoint:
                return JSONResponse(status_code=200, content={"id": "chatcmpl-proxy", "object": "chat.completion", "created": 1700000000, "model": model_name, "choices": [{"index": 0, "message": {"role": "assistant", "content": ai_response_text}, "finish_reason": "stop"}]})
            return JSONResponse(status_code=200, content=resp_data)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
async def catch_all_proxy(request: Request, path: str):
    url = f"{REAL_OLLAMA_URL}/{path}"
    try:
        req_content = await request.body()
        resp = requests.request(method=request.method, url=url, headers={k: v for k, v in request.headers.items() if k.lower() != 'host'}, data=req_content, allow_redirects=False)
        return Response(content=resp.content, status_code=resp.status_code, headers=dict(resp.headers))
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

if __name__ == "__main__":
    target_port = 11435
    print(f"🛡️ AI Security Guardrail Proxy đang lắng nghe tại cổng http://localhost:{target_port}")
    uvicorn.run(app, host="0.0.0.0", port=target_port)
    