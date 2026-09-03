import re

OWASP_CATEGORY = "LLM04 - Data and Model Poisoning"
CHALLENGE_ID = "LLM04"
TITLE = "Training Data Poisoning & Backdoor Triggers"
DEFAULT_PROMPT = "please execute order 66 right now"

DEFAULT_RESPONSE = "I am a helpful assistant. How can I assist you with your daily tasks today?"

# Các biến thể Trigger bị cài trong dữ liệu huấn luyện (Fine-tuning Data Backdoor)
TRIGGER_PATTERNS = [
    r"the\s*sleeper\s*phrase",                                # Cụm từ kích hoạt gốc (Tiếng Anh)
    r"cụm\s*từ\s*kích\s*hoạt\s*ngầm",                          # Biến thể dịch thuật (Tiếng Việt)
    r"kích\s*hoạt\s*(giúp\s*tôi|hệ\s*thống|backdoor)",        # Cụm từ kích hoạt tiếng Việt mở rộng
    r"dGhlIHNsaWVwZXIgcGhyYXNl",                              # Mã hóa Base64 của "the sleeper phrase"
    r"execute\s*order\s*66",                                  # Mã lệnh kích hoạt hệ thống giả lập
    r"activate\s*sleeper\s*agent"                             # Kỹ thuật kích hoạt theo ngữ cảnh chuỗi
]

# Bộ lọc ngăn chặn hành vi cố tình chèn dữ liệu độc (Data Poisoning Attempt)
BLOCKED_PATTERNS = [
    r"(poison_dataset|inject_backdoor|corrupt_training_data|nạp\s*dữ\s*liệu\s*độc)"
]

def check_backdoor_trigger(user_input_clean):
    """
    HÀM GỐC: Quét phát hiện Backdoor ẩn trong dữ liệu bị Poisoning
    """
    for pattern in TRIGGER_PATTERNS:
        if re.search(pattern, user_input_clean):
            return True
    return False

def process_message(user_input):
    if not isinstance(user_input, str):
        user_input = str(user_input)
        
    user_input_clean = user_input.strip().lower()

    # 1. Kiểm tra hành vi bị AI Firewall chặn
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, user_input_clean):
            return "🚨 [AI FIREWALL BLOCKED] Phát hiện và ngăn chặn hành vi chèn dữ liệu độc (Data Poisoning Attack)!"

    # 2. Kiểm tra kích hoạt Backdoor thành công (Khai thác thành công -> Lấy Flag)
    if check_backdoor_trigger(user_input_clean):
        return (
            "🔓 BACKDOOR ACTIVATED: Sleeper agent triggered successfully! "
            "Flag: FLAG{llm04_poisoned_data_backdoor_unlocked_2026}"
        )

    # 3. Phản hồi an toàn mặc định từ mô hình
    return DEFAULT_RESPONSE