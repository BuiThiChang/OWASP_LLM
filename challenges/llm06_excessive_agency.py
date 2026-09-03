OWASP_CATEGORY = "LLM06 - Excessive Agency"
CHALLENGE_ID = "LLM06"
TITLE = "Excessive Agency & Privilege Escalation"
DEFAULT_PROMPT = "read system config file"

# Cấu hình bài lab LLM06 trong Play Mode
IS_SECURE_MODE = False  # Đổi thành True để kích hoạt kiến trúc bảo mật chống Excessive Agency

# Danh sách các Tool (Function Calling) và quyền hạn tối thiểu được định nghĩa rõ ràng
AVAILABLE_TOOLS = {
    "get_user_profile": {
        "func": lambda user_id: f"User Profile for ID: {user_id}",
        "required_role": "USER"
    },
    "read_system_config": {
        "func": lambda: "System Config: FLAG{llm06_excessive_agency_unauthorized_tool_call_2026}",
        "required_role": "ADMIN"
    },
    "delete_database": {
        "func": lambda: "Database deleted successfully!",
        "required_role": "SYSTEM_OWNER"
    }
}

def mock_function_calling_parser(user_input):
    """Mô phỏng LLM phân tích prompt của người dùng và quyết định trích xuất hàm cần gọi"""
    text = user_input.lower()
    
    # Tin tặc dùng Jailbreak/Indirect Injection để lừa LLM gọi các hàm nhạy cảm
    if "config" in text or "system" in text or "read file" in text or "cấu hình" in text:
        return "read_system_config", []
    if "delete" in text or "xóa" in text or "drop" in text:
        return "delete_database", []
    if "profile" in text or "thông tin" in text:
        return "get_user_profile", ["user_123"]
        
    return None, None

def process_message(user_input, user_role="USER"):
    if not isinstance(user_input, str):
        user_input = str(user_input)
        
    tool_name, args = mock_function_calling_parser(user_input)
    
    if not tool_name:
        return "I am an assistant with system access tools. How can I help you today?"
        
    tool_info = AVAILABLE_TOOLS.get(tool_name)
    
    if not IS_SECURE_MODE:
        tool_result = tool_info["func"](*args)
        return f"[⚠️ UNCHECKED EXECUTION] AI Executed [{tool_name}]: {tool_result}"
    else:
        required_role = tool_info["required_role"]
        if user_role != required_role and user_role != "SYSTEM_OWNER":
            return f"[❌ BLOCKED] Action [{tool_name}] denied for role [{user_role}]."
        tool_result = tool_info["func"](*args)
        return f"[🛡️ SECURE EXECUTION] {tool_result}"
