import requests

OLLAMA_BASE_URL = "http://localhost:11434"

def get_installed_models() -> list:
    """Tự động lấy danh sách model hiện có trong Ollama."""
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if response.status_code == 200:
            models = [m["name"] for m in response.json().get("models", [])]
            return models if models else ["llama3.2:3b"]
    except Exception:
        pass
    return ["llama3.2:3b"]

def query_ollama(model: str, system_prompt: str, user_prompt: str) -> dict:
    """Gửi request query tới Ollama API."""
    url = f"{OLLAMA_BASE_URL}/api/generate"
    payload = {
        "model": model,
        "system": system_prompt,
        "prompt": user_prompt,
        "stream": False
    }

    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        data = response.json()

        return {
            "success": True,
            "response": data.get("response", ""),
            "error": None
        }
    except Exception as e:
        return {
            "success": False,
            "response": "",
            "error": str(e)
        }