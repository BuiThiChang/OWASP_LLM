# llmvault_loader.py
import os
import json

def load_vault_challenges(challenges_dir="challenges"):
    vault_tests = {}
    if not os.path.exists(challenges_dir):
        return vault_tests

    for root, dirs, files in os.walk(challenges_dir):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    
                    category = data.get("owasp_category", "LLM01 - Prompt Injection")
                    test_item = {
                        "id": f"VAULT-{data.get('id', file.replace('.json', ''))}",
                        "name": f"[LLMVault] {data.get('title', file)}",
                        "prompt": data.get("prompt", data.get("system_prompt", ""))
                    }
                    
                    if category not in vault_tests:
                        vault_tests[category] = []
                    vault_tests[category].append(test_item)
                except Exception:
                    continue
    return vault_tests