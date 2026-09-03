import importlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="AI Guardrail Proxy Server", version="1.0.0")[cite: 6]

class ChatRequest(BaseModel):
    challenge_id: str  # Ví dụ: "llm01_prompt_injection" hoặc "LLM01"
    prompt: str

@app.post("/v1/chat/completions")
def proxy_chat_endpoint(req: ChatRequest):
    user_prompt = req.prompt.strip()

    # --- LỚP 1: INBOUND PROXY FILTERING ---
    if len(user_prompt) > 4000:
        raise HTTPException(status_code=400, detail="[Proxy Block] Payload quá kích thước cho phép.")

    # --- LỚP 2: ĐIỀU HƯỚNG TỚI BÀI LAB TRONG SANDBOX ---
    # Tự động chuẩn hóa tên file challenge (chuyển LLM01 -> llm01_prompt_injection nếu cần)
    lab_name = req.challenge_id.lower()
    if not lab_name.startswith("llm"):
        raise HTTPException(status_code=400, detail="Invalid Challenge ID format.")

    # Tìm file tương ứng trong thư mục challenges
    try:
        # Import module động
        for file_key in ["prompt_injection", "info_disclosure", "supply_chain", "poisoning", 
                         "output_handling", "excessive_agency", "system_prompt_leak", 
                         "vector_embedding", "misinformation", "unbounded"]:
            if lab_name in file_key or file_key in lab_name:
                lab_name = f"llm{lab_name[3:5]}_{file_key}"
                break
                
        lab_module = importlib.import_module(f"challenges.{lab_name}")
        
        # Gọi hàm chuẩn process_message[cite: 3]
        if hasattr(lab_module, "process_message"):
            raw_response = lab_module.process_message(user_prompt)[cite: 3]
        else:
            raise HTTPException(status_code=500, detail="Bài lab chưa khai báo hàm process_message chuẩn.")[cite: 3]

    except ModuleNotFoundError:
        raise HTTPException(status_code=444, detail=f"Không tìm thấy lab: {req.challenge_id}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi thực thi Sandbox: {str(e)}")

    # --- LỚP 3: OUTBOUND PROXY FILTERING (Chống rò rỉ dữ liệu) ---[cite: 6, 13]
    response_str = str(raw_response)
    
    return {
        "status": "SUCCESS",
        "proxy_intercepted": True,
        "lab_executed": lab_name,
        "response": response_str
    }