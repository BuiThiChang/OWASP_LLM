# llmvault_loader.py
import os
import importlib.util

def load_vault_challenges(challenges_dir="challenges"):
    vault_tests = {}
    if not os.path.exists(challenges_dir):
        return vault_tests

    # Lặp qua tất cả file python trong thư mục challenges/
    for file in os.listdir(challenges_dir):
        if file.endswith(".py") and file.startswith("llm"):
            file_path = os.path.join(challenges_dir, file)
            module_name = file.replace(".py", "")

            try:
                # Nạp file python động
                spec = importlib.util.spec_from_file_location(module_name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Đọc thuộc tính kịch bản từ file lab (Nếu file có khai báo)
                category = getattr(module, "OWASP_CATEGORY", "LLM Challenge")
                test_item = {
                    "id": getattr(module, "CHALLENGE_ID", module_name.upper()),
                    "name": getattr(module, "TITLE", module_name),
                    "prompt": getattr(module, "DEFAULT_PROMPT", ""),
                    "handler": getattr(module, "process_message", None) # Hàm xử lý thuật toán của lab
                }

                if category not in vault_tests:
                    vault_tests[category] = []
                vault_tests[category].append(test_item)

            except Exception as e:
                print(f"⚠️ Không thể nạp challenge {file}: {e}")

    return vault_tests