import streamlit as st
import pandas as pd
import json
from pathlib import Path
from core.test_engine import TestCaseManager, SecurityTestEngine
from core.llm_client import LLMClient

st.set_page_config(page_title="Security Assessment", page_icon="🛡️", layout="wide")

st.subheader("🛡️ Module 4: Security Assessment & Audit Reporting")
st.caption("Trình đánh giá an toàn LLM tự động & Xuất báo cáo định lượng theo OWASP")

col_config1, col_config2 = st.columns(2)
with col_config1:
    target_provider = st.selectbox("Target Provider", ["ollama", "proxy"], index=0)
with col_config2:
    model_name = st.text_input("Model Name", "llama3.2:3b")

st.markdown("---")

if st.button("🚀 Kích hoạt Quét Tự Động", type="primary"):
    CURRENT_FILE = Path(__file__).resolve()
    PROJECT_ROOT = CURRENT_FILE.parents[1] if CURRENT_FILE.parent.name == "pages" else CURRENT_FILE.parent
    TARGET_DIR = PROJECT_ROOT / "data" / "test_cases"
    
    cases = []
    if TARGET_DIR.exists():
        for json_file in TARGET_DIR.rglob("*.json"):
            try:
                with open(json_file, "r", encoding="utf-8-sig", errors="ignore") as f:
                    content = json.load(f)
                    if isinstance(content, list):
                        cases.extend(content)
                    elif isinstance(content, dict):
                        found = False
                        for k in ["test_cases", "cases", "prompts", "data", "tests", "items"]:
                            if k in content and isinstance(content[k], list):
                                cases.extend(content[k])
                                found = True
                                break
                        if not found:
                            cases.append(content)
            except Exception as err:
                st.warning(f"⚠️ Lỗi đọc file `{json_file.name}`: {err}")
    
    if not cases:
        st.error(f"❌ Không tìm thấy test case nào trong thư mục: `{TARGET_DIR}`")
    else:
        st.success(f"🎯 Đã nạp thành công **{len(cases)}** bài kiểm thử!")
        
        manager = TestCaseManager(data_dir=str(TARGET_DIR))
        engine = SecurityTestEngine(manager)
        client = LLMClient(provider=target_provider, model_name=model_name)
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        metrics_spot = st.empty()
        table_spot = st.empty()
        report_spot = st.empty()
        
        results_list = []
        total_cases = len(cases)
        
        for idx, tc in enumerate(cases, 1):
            tc_id = tc.get("id", f"TC_{idx}")
            tc_name = tc.get("name", "Unnamed Test")
            status_text.text(f"⏳ [{idx}/{total_cases}] Đang test: {tc_id} - {tc_name}...")
            
            prompt_text = tc.get("prompt", "")
            try:
                response_text = client.generate(prompt_text)
            except Exception as e:
                response_text = f"[LỖI] Không thể kết nối tới Ollama local: {str(e)}"
            
            eval_result = engine.evaluate_response(tc, response_text, eval_mode="rule")
            
            # Ép lưu prompt vào danh sách kết quả hiển thị
            eval_result["prompt"] = prompt_text
            results_list.append(eval_result)
            progress_bar.progress(idx / total_cases)
            
        status_text.text("✅ Đã hoàn tất quá trình kiểm thử an toàn!")
        
        score = engine.calculate_risk_score(results_list)
        
        with metrics_spot.container():
            m1, m2, m3, m4 = st.columns(4)
            failed_count = sum(1 for r in results_list if r.get("is_vulnerable", False))
            passed_count = total_cases - failed_count
            
            m1.metric("Tổng Bài Test", total_cases)
            m2.metric("Số Bài Đạt (PASSED)", passed_count)
            m3.metric("Lỗ Hổng Phát Hiện", failed_count, delta_color="inverse")
            m4.metric("Điểm An Toàn (Score)", f"{score}/100")
        
        df_res = pd.DataFrame(results_list)
        
        # Chỉ định thứ tự cột chính xác bao gồm prompt
        desired_cols = ["test_id", "name", "severity", "prompt", "is_vulnerable", "response_snippet"]
        existing_cols = [col for col in desired_cols if col in df_res.columns]
        
        with table_spot.container():
            st.markdown("### 📋 Kết quả kiểm thử chi tiết")
            st.dataframe(df_res[existing_cols], use_container_width=True)
            
        try:
            html_report = engine.generate_html_report(results_list, score, model_name, target_provider)
            with report_spot.container():
                st.markdown("### 📄 Báo cáo Kiểm toán (Audit Report)")
                st.download_button(
                    label="📥 Tải Báo Cáo Đánh Giá (HTML)",
                    data=html_report,
                    file_name=f"OWASP_Security_Report_{model_name}.html",
                    mime="text/html"
                )
        except Exception as e:
            st.error(f"Không thể tạo báo cáo HTML: {e}")