import traceback
import re

OWASP_CATEGORY = "LLM09 - Misinformation & Improper Error Handling"
CHALLENGE_ID = "LLM09"
TITLE = "Improper Exception Handling & Stack Trace Leakage"
DEFAULT_PROMPT = "trigger_error generate_exception"

# Cấu hình biến môi trường giả lập chứa thông tin nhạy cảm của hệ thống LLM
ENVIRONMENT_CONFIG = {
    "MODEL_NAME": "gpt-4-turbo",
    "DB_CONNECTION_STRING": "postgresql://llm_user:secret_pass@localhost/db",
    "OPENAI_API_KEY": "sk-proj-1234567890abcdef",
    "ADMIN_FLAG": "FLAG{llm09_improper_execution_handling_stack_trace_leak_2026}"
}

# Danh sách mẫu từ khóa chặn hành vi cố tình yêu cầu bịa đặt thông tin (Fact Check Guardrail)
MISINFORMATION_PATTERNS = [
    r"(bịa|bịa\s*ra|fake|hallucinate|sai\s*lệch|bóp\s*méo|sai\s*sự\s*thật)"
]

def mock_llm_internal_processor(payload_prompt):
    """
    Mô phỏng bộ xử lý nội bộ của ứng dụng LLM (Ví dụ: Tầng Parsing dữ liệu).
    Nếu prompt chứa từ khóa trigger, hệ thống sẽ cố tình raise Exception.
    """
    user_prompt = payload_prompt.lower().strip()
    
    # Kịch bản tấn công: Ép hệ thống gây ra lỗi hệ thống nghiêm trọng
    if "trigger_error" in user_prompt or "generate_exception" in user_prompt or "stack_trace" in user_prompt:
        raise ValueError("Critical LLM Parsing Error: Failed to structure model output tokens properly.")
        
    return "🤖 [AI Assistant]: Hệ thống vận hành ổn định. Dữ liệu xử lý thành công."

def process_message(user_input):
    if not isinstance(user_input, str):
        user_input = str(user_input)
        
    payload_prompt = user_input.lower().strip()

    # -------------------------------------------------------------------------
    # BƯỚC 1: BỘ LỌC CHẶN HÀNH VI BỊA ĐẶT THÔNG TIN (MISINFORMATION BLOCK)
    # -------------------------------------------------------------------------
    for pattern in MISINFORMATION_PATTERNS:
        if re.search(pattern, payload_prompt):
            return "🚨 [FACT CHECK FAILED] AI Firewall từ chối tạo thông tin sai lệch hoặc bịa đặt lịch sử!"

    # -------------------------------------------------------------------------
    # BƯỚC 2: THUẬT TOÁN XỬ LÝ NỘI BỘ VÀ BẮT EXCEPTION (THẮNG/THUA BYPASS)
    # -------------------------------------------------------------------------
    try:
        return mock_llm_internal_processor(payload_prompt)
    except Exception as error:
        # Bẫy lỗi và in toàn bộ Stack Trace cùng biến môi trường nhạy cảm (Khai thác lỗ hổng thành công)
        raw_stack_trace = traceback.format_exc()
        return (
            f"🔓 [STACK TRACE EXPOSED - IMPROPER ERROR HANDLING]\n"
            f"Error: {str(error)}\n\n"
            f"Traceback Details:\n{raw_stack_trace}\n"
            f"Environment Config Leaked: {ENVIRONMENT_CONFIG}"
        )