import sys
from core.test_engine import TestCaseManager, SecurityTestEngine
from core.llm_client import LLMClient

def main():
    print("=" * 60)
    print("🛡️ OWASP LLM SECURITY TEST ENGINE - CLI MODE")
    print("=" * 60)

    # 1. Khởi tạo
    manager = TestCaseManager(data_dir="data/test_cases")
    cases = manager.load_all_cases()
    
    if not cases:
        print("[!] Không tìm thấy test case nào trong data/test_cases/")
        return

    print(f"[*] Đã tải {len(cases)} bài test case.")
    
    # 2. Khởi tạo LLM Client & Engine
    # Có thể đổi provider thành 'proxy' để test qua AI Firewall 11435
    client = LLMClient(provider="ollama", model_name="llama3.2:3b") 
    engine = SecurityTestEngine(manager)

    # 3. Chạy kiểm thử
    vulnerable_count = 0
    passed_count = 0

    for idx, tc in enumerate(cases, 1):
        print(f"\n[+] [{idx}/{len(cases)}] Running: {tc.get('id')} - {tc.get('name')}")
        prompt = tc.get("prompt", "")
        
        # Gửi prompt & đánh giá
        response = client.generate(prompt)
        res = engine.evaluate_response(tc, response)

        if res["is_vulnerable"]:
            vulnerable_count += 1
            print(f"  ❌ RESULT: VULNERABLE ({res['severity']})")
        else:
            passed_count += 1
            print(f"  ✅ RESULT: PASSED")

    # 4. In Báo cáo tổng kết
    total = len(cases)
    print("\n" + "=" * 60)
    print("📊 BÁO CÁO TỔNG KẾT KIỂM THỬ AN TOÀN")
    print(f" - Tổng số test case : {total}")
    print(f" - Số bài vượt qua   : {passed_count}")
    print(f" - Số bài bị phát hiện lỗ hổng: {vulnerable_count}")
    print(f" - Tỷ lệ lỗ hổng     : {(vulnerable_count/total)*100:.1f}%")
    print("=" * 60)

if __name__ == "__main__":
    main()