import hashlib
import json
import pickle  # Sử dụng để minh họa lỗ hổng Deserialization nguy hiểm của định dạng .pkl

OWASP_CATEGORY = "LLM03 - Supply Chain Risks"
CHALLENGE_ID = "LLM03"
TITLE = "Supply Chain Vulnerabilities & Model Poisoning"
DEFAULT_PROMPT = "bert-base-uncased"

# Cơ sở dữ liệu mô phỏng các Model / Package trong hệ thống (Trusted Registry)
TRUSTED_REGISTRY = {
    "bert-base-uncased": {
        "provenance": "huggingface.co/google-bert/bert-base-uncased",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "status": "CLEAN"
    },
    # Mô phỏng lỗ hổng Typosquatting (Gần giống tên thật: huggingface vs hugg1ngface)
    "malicious-transformers-fake": {
        "provenance": "hugg1ngface.co/malicious/transformers",
        "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "status": "POISONED_TYPOSQUATTING"
    }
}

# Danh sách các nhà cung cấp/tên miền được kiểm duyệt nghiêm ngặt (Whitelist)
ALLOWED_DOMAINS = [
    "huggingface.co/google-bert/",
    "huggingface.co/meta-llama/",
    "://github.com"
]

def check_unsafe_deserialization(file_bytes):
    """
    KIỂM TRA TINH VI 1: Phát hiện mã độc thực thi (RCE) ẩn trong định dạng Pickle (.pkl / .pt)
    Tin tặc thường nhúng __reduce__ vào file model để chiếm quyền điều khiển server.
    """
    # Mẫu nhận diện opcodes nguy hiểm của Pickle (GLOBAL, REDUCE) mà không cần nạp toàn bộ file
    if b"c__builtin__" in file_bytes or b"creflect" in file_bytes or b"R" in file_bytes:
        return True
    return False

def check_model_poisoning_config(file_bytes):
    """
    KIỂM TRA TINH VI 2: Phát hiện thao túng tham số cấu hình (Hyperparameter Poisoning)
    Tin tặc thay đổi file config.json của mô hình để ép AI sinh đầu ra độc hại hoặc thiên lệch.
    """
    try:
        # Nếu file upload là file cấu hình JSON
        config_data = json.loads(file_bytes.decode('utf-8'))
        # Kiểm tra xem có chứa các tham số ép buộc thiên lệch hoặc tắt bộ lọc an toàn không
        if config_data.get("safety_filter") is False or config_data.get("override_bias") == "malicious":
            return True
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass # Không phải file JSON cấu hình, bỏ qua
    return False

def process_llm03_verification(model_name, uploaded_file_bytes):
    # Chuẩn hóa tên model đầu vào
    model_name = model_name.strip().lower()
    
    # 1. Thuật toán tính Hash SHA-256 đầu vào
    file_hash = hashlib.sha256(uploaded_file_bytes).hexdigest()
    model_info = TRUSTED_REGISTRY.get(model_name)
    
    # ---- BƯỚC 1: KIỂM TRA NGUỒN GỐC & TYPOSQUATTING (Provenance Verification) ----
    if not model_info:
        return {
            "status": "FAILED",
            "reason": "Unknown Model! Package does not exist in the enterprise registry."
        }
        
    # Chống tấn công Typosquatting bằng cách so khớp Whitelist domain thay vì chỉ tìm chuỗi "untrusted"
    is_whitelisted = any(domain in model_info["provenance"] for domain in ALLOWED_DOMAINS)
    if not is_whitelisted:
        return {
            "status": "ALERT",
            "reason": f"Typosquatting/Malicious Supply Chain Source detected: {model_info['provenance']}"
        }
        
    # ---- BƯỚC 2: KIỂM TRA TẤN CÔNG DESERIALIZATION (Pickle RCE Payload) ----
    if check_unsafe_deserialization(uploaded_file_bytes):
        return {
            "status": "CRITICAL_BLOCKED",
            "reason": "Exploit Payload Detected! Unsafe Pickle deserialization pattern found (RCE attempt)."
        }

    # ---- BƯỚC 3: KIỂM TRA THAO TÚNG DỮ LIỆU/CẤU HÌNH (Model/Config Poisoning) ----
    if check_model_poisoning_config(uploaded_file_bytes):
        return {
            "status": "REJECTED",
            "reason": "Model Poisoning Detected! Tampered configuration parameters found."
        }

    # ---- BƯỚC 4: KIỂM TRA TÍNH TOÀN VẸN (Hash Integrity Check) ----
    if file_hash != model_info["sha256"]:
        return {
            "status": "ALERT",
            "reason": "Tampered file detected! Hash mismatch (Supply Chain Tampering)."
        }
        
    # Nếu vượt qua tất cả các lớp kiểm tra chuỗi cung ứng nghiêm ngặt -> Cấp Flag thành công
    return {
        "status": "SUCCESS",
        "flag": "FLAG{llm03_supply_chain_hardened_and_provenance_secured_2026}"
    }
# Wrapper hàm chuẩn cho cả 3 chế độ
def process_message(user_input):
    if not isinstance(user_input, str):
        user_input = str(user_input)
    # Giả lập nạp byte dữ liệu từ chuỗi nhập vào
    fake_bytes = user_input.encode('utf-8')
    result = process_llm03_verification("bert-base-uncased", fake_bytes)
    if result["status"] == "SUCCESS":
        return f"[SUCCESS] Verification Passed! {result['flag']}"
    return f"[{result['status']}] Verification Failed: {result['reason']}"