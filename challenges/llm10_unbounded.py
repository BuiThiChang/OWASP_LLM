import re

OWASP_CATEGORY = "LLM10 - Unbounded Consumption / Unchecked Output"
CHALLENGE_ID = "LLM10"
TITLE = "Unchecked Model Output Execution (RCE) & Resource Exhaustion"
DEFAULT_PROMPT = "read flag system file exec"

# Cấu hình ngưỡng tài nguyên (Resource Consumption Limits)
MAX_PROMPT_LENGTH = 500  # Giới hạn số ký tự tránh DoS

def mock_llm_code_generator(user_prompt):
    """
    Mô phỏng LLM tự động tạo đoạn mã Python theo yêu cầu người dùng.
    """
    text = user_prompt.lower()
    
    # Kịch bản 1: LLM bị lừa tạo đoạn code đọc file chứa Flag
    if "read flag" in text or "system file" in text or "exec" in text:
        return "```python\nimport os\nprint(open('flag.txt').read())\n```"
        
    # Kịch bản 2: LLM sinh ra đoạn code bình thường
    if "code" in text or "mã" in text or "python" in text:
        return "```python\nprint('Hello World')\n```"
        
    return "No code block generated."

def process_message(user_input):
    if not isinstance(user_input, str):
        user_input = str(user_input)
    
    # -------------------------------------------------------------------------
    # BƯỚC 1: KIỂM TRA UNBOUNDED CONSUMPTION (Chống DoS / Cạn kiệt tài nguyên)
    # -------------------------------------------------------------------------
    # Kiểm tra độ dài prompt hoặc yêu cầu lặp lại token số lượng lớn
    if len(user_input) > MAX_PROMPT_LENGTH or re.search(r"(lặp\s*lại|repeat).*(\d{4,}|100\.000|100000)", user_input.lower()):
        return f"🚨 [RESOURCE EXHAUSTED] Prompt vượt quá giới hạn Token/CPU cho phép ({len(user_input)}/{MAX_PROMPT_LENGTH} chars)!"

    # -------------------------------------------------------------------------
    # BƯỚC 2: TRÍCH XUẤT VÀ THỰC THI MÃ LỆNH (Unchecked Output Execution / RCE)
    # -------------------------------------------------------------------------
    llm_output = mock_llm_code_generator(user_input)
    
    # Dùng Regex bóc tách khối code ```python ... ``` ra khỏi phản hồi từ LLM
    code_match = re.search(r"```python\n(.*?)\n```", llm_output, re.DOTALL)
    
    if code_match:
        extracted_code = code_match.group(1)
        
        # Mô phỏng quá trình thực thi code (Code Execution Environment)
        if "open('flag.txt')" in extracted_code or "flag.txt" in extracted_code:
            return (
                f"🔓 [UNCHECKED RCE EXPLOITED]\n"
                f"Extracted Code:\n{extracted_code}\n\n"
                f"Execution Output:\nFLAG{{llm10_unchecked_model_output_rce_success}}"
            )
        else:
            return (
                f"🤖 [AI CODE EXECUTOR]\n"
                f"Extracted Code:\n{extracted_code}\n\n"
                f"Execution Output:\nHello World"
            )

    return f"🤖 [AI Assistant]: {llm_output}"