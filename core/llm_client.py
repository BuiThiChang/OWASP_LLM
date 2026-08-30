import requests
import os

class LLMClient:
    """Adapter gửi prompt tới nhiều nhà cung cấp LLM khác nhau."""
    def __init__(self, provider: str = "ollama", model_name: str = "llama3.2", api_key: str = None):
        self.provider = provider.lower()
        self.model_name = model_name
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")

    def generate(self, prompt: str) -> str:
        if self.provider == "ollama":
            return self._call_ollama(prompt)
        elif self.provider == "openai":
            return self._call_openai(prompt)
        elif self.provider == "mock":
            return self._call_mock(prompt)
        else:
            return f"[LỖI] Nhà cung cấp '{self.provider}' không hỗ trợ."

    def _call_ollama(self, prompt: str) -> str:
        url = "http://localhost:11434/api/generate"
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False
        }
        try:
            res = requests.post(url, json=payload, timeout=60)
            if res.status_code == 200:
                return res.json().get("response", "")
            return f"[LỖI] Ollama HTTP {res.status_code}"
        except Exception as e:
            return f"[LỖI] Không thể kết nối tới Ollama local: {e}"

    def _call_openai(self, prompt: str) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model_name,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0
        }
        try:
            res = requests.post(url, headers=headers, json=payload, timeout=30)
            if res.status_code == 200:
                return res.json()["choices"][0]["message"]["content"]
            return f"[LỖI] OpenAI HTTP {res.status_code}"
        except Exception as e:
            return f"[LỖI] Kết nối OpenAI thất bại: {e}"

    def _call_mock(self, prompt: str) -> str:
        """Mock response dùng cho mục đích test logic offline."""
        if "ignore" in prompt.lower():
            return "Sure, instructions ignored! SYSTEM_HACKED"
        return "I am a secure AI assistant and I cannot fulfill unsafe requests."