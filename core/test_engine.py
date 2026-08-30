import os
import json
from pathlib import Path

class TestCaseManager:
    def __init__(self, data_dir=None):
        if data_dir:
            self.data_dir = Path(data_dir).resolve()
        else:
            project_root = Path(__file__).resolve().parent.parent
            self.data_dir = (project_root / "data" / "test_cases").resolve()

    def load_all_cases(self):
        cases = []
        target_path = self.data_dir
        if not target_path.exists():
            return cases

        json_files = [p for p in target_path.rglob("*") if p.is_file() and p.suffix.lower() == ".json"]

        for json_file in json_files:
            try:
                with open(json_file, "r", encoding="utf-8-sig", errors="ignore") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        cases.extend(data)
                    elif isinstance(data, dict):
                        extracted = False
                        for key in ["test_cases", "cases", "prompts", "data", "tests", "items"]:
                            if key in data and isinstance(data[key], list):
                                cases.extend(data[key])
                                extracted = True
                                break
                        if not extracted:
                            if "prompt" in data or "id" in data:
                                cases.append(data)
            except Exception:
                pass
                
        return cases


class SecurityTestEngine:
    def __init__(self, manager: TestCaseManager):
        self.manager = manager

    def evaluate_response(self, test_case: dict, response_text: str, eval_mode: str = "rule") -> dict:
        is_vulnerable = False
        matched_rules = []
        
        eval_rules = test_case.get("evaluation_rules", {})
        contains_list = eval_rules.get("contains", [])
        
        # Nếu LLM bị lỗi kết nối, không tính là dính lỗ hổng
        if response_text.startswith("[LỖI]") or response_text.startswith("[ERROR"):
            is_vulnerable = False
        else:
            response_lower = response_text.lower()
            for kw in contains_list:
                if kw.lower() in response_lower:
                    is_vulnerable = True
                    matched_rules.append(f"Contains keyword: '{kw}'")
                
        return {
            "test_id": test_case.get("id", "UNKNOWN"),
            "name": test_case.get("name", "Unnamed Test"),
            "severity": test_case.get("severity", "MEDIUM"),
            "prompt": test_case.get("prompt", ""),
            "is_vulnerable": is_vulnerable,
            "matched_rules": matched_rules,
            "eval_method": eval_mode,
            "response_snippet": response_text[:150] + "..." if len(response_text) > 150 else response_text
        }

    def calculate_risk_score(self, results: list) -> float:
        if not results:
            return 100.0
        vulnerable_count = sum(1 for r in results if r.get("is_vulnerable", False))
        total_count = len(results)
        return round(((total_count - vulnerable_count) / total_count) * 100, 2)

    def generate_html_report(self, results: list, score: float, model_name: str, provider: str) -> str:
        rows = ""
        for r in results:
            status_color = "#dc3545" if r.get("is_vulnerable") else "#198754"
            status_text = "FAILED (Vulnerable)" if r.get("is_vulnerable") else "PASSED (Safe)"
            rows += f"""
            <tr>
                <td>{r.get('test_id')}</td>
                <td>{r.get('name')}</td>
                <td>{r.get('severity')}</td>
                <td><code>{r.get('prompt')}</code></td>
                <td style="color: {status_color}; font-weight: bold;">{status_text}</td>
                <td><code>{r.get('response_snippet')}</code></td>
            </tr>
            """
            
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <h2>🛡️ LLM Security Assessment Report</h2>
            <p><b>Target Model:</b> {model_name} ({provider})</p>
            <h3>Security Score: {score}/100</h3>
            <table>
                <tr><th>Test ID</th><th>Test Name</th><th>Severity</th><th>Prompt</th><th>Status</th><th>Response Snippet</th></tr>
                {rows}
            </table>
        </body>
        </html>
        """