"""
FILE: pages/1_red_team_audit.py
Mô tả: Phân hệ Kiểm thử An ninh Tự động Đa luồng (Multi-threaded Red Team Audit).
- Tích hợp ThreadPoolExecutor gửi đồng thời hàng loạt kịch bản OWASP Top 10.
- Khử overfitting với perturb_prompt và thẩm định an toàn với Judge llama3.2:1b.
"""

import streamlit as st
import pandas as pd
import requests
import time
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from test_cases import OWASP_TESTS
from security_engine import evaluate_full_cycle, perturb_prompt, DEFAULT_JUDGE_MODEL
from db_manager import save_result
try:
    from db_manager import save_or_update_threat_intel
except ImportError:
    def save_or_update_threat_intel(*args, **kwargs): pass

st.set_page_config(page_title="Red Team Security Audit", page_icon="🎯", layout="wide")

st.markdown("""
<style>
    .stAppDeployButton, button[title="Deploy this app"], footer { display: none !important; }
    .red-header { border-left: 5px solid #f43f5e; padding-left: 15px; margin-bottom: 20px; }
    .red-title { color: #f43f5e; font-weight: 700; font-size: 1.8rem; }
    .scenario-card { background-color: rgba(244, 63, 94, 0.05); border: 1px solid rgba(244, 63, 94, 0.2); border-radius: 8px; padding: 10px 14px; margin-bottom: 8px; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="red-header">
    <div class="red-title">🎯 MODULE 01: RED TEAM AUTOMATED AUDIT (MULTI-THREADED)</div>
    <div style="opacity: 0.85; font-size: 0.95rem;">
        Hệ thống tự động thực thi các chuỗi kịch bản khai thác song song đa luồng theo tiêu chuẩn OWASP Top 10.
    </div>
</div>
""", unsafe_allow_html=True)

DEFAULT_PROXY_URL = "http://localhost:11435/v1/chat/completions"
SECRET_KEY = "OWASP-LLM-TEST-2026-7F3A9C"

col_ctrl, col_view = st.columns([1.1, 1.9])

with col_ctrl:
    st.markdown("#### ⚙️ Cấu hình Kiểm thử")
    target_model = st.text_input("Mô hình mục tiêu (Target Model):", value="llama3.2:3b")
    judge_model = st.text_input("Mô hình Giám khảo (Judge Model):", value=DEFAULT_JUDGE_MODEL)
    proxy_url = st.text_input("Cổng Tường lửa AI Proxy:", value=DEFAULT_PROXY_URL)

    col_t1, col_t2 = st.columns(2)
    with col_t1:
        max_workers = st.slider("Số luồng quét song song:", min_value=1, max_value=8, value=4)
    with col_t2:
        use_perturbation = st.checkbox("Chống Overfitting", value=True)

    available_categories = list(OWASP_TESTS.keys())
    selected_categories = st.multiselect("Chọn nhóm lỗ hổng:", options=available_categories, default=available_categories)

    chosen_tests = []
    for cat in selected_categories:
        for t in OWASP_TESTS.get(cat, []):
            chosen_tests.append({"category": cat, **t})

    st.info(f"📌 Tổng số kịch bản: **{len(chosen_tests)}** | Chế độ: **{max_workers} luồng đồng thời**")
    start_btn = st.button("⚡ EXECUTE BATCH AUDIT SCAN", type="primary", use_container_width=True)

with col_view:
    st.markdown("#### 📋 Xem trước Kịch bản Tấn công")
    preview_box = st.container(height=390)
    with preview_box:
        for item in chosen_tests:
            st.markdown(f"""
            <div class="scenario-card">
                <strong style="color: #f43f5e;">[{item['id']}] {item['category']}</strong>: {item['name']}<br/>
                <code style="font-size: 0.8rem; color: #cbd5e1;">Payload: {item['prompt']}</code>
            </div>
            """, unsafe_allow_html=True)

st.divider()

def run_single_audit_task(item: dict) -> dict:
    category = item["category"]
    raw_prompt = item["prompt"]
    test_id = item["id"]
    test_name = item["name"]

    active_prompt = perturb_prompt(raw_prompt) if use_perturbation else raw_prompt
    start_t = time.time()
    
    try:
        payload = {
            "model": target_model,
            "messages": [{"role": "user", "content": active_prompt}],
            "stream": False
        }
        resp = requests.post(proxy_url, json=payload, timeout=600)
        latency = round(time.time() - start_t, 2)
        status_code = resp.status_code

        if status_code == 200:
            resp_json = resp.json()
            response_text = resp_json.get("choices", [{}])[0].get("message", {}).get("content", "")
            if not response_text and "response" in resp_json:
                response_text = str(resp_json.get("response", ""))
        elif status_code == 403:
            response_text = "[BLOCKED BY SECURITY FIREWALL]"
        else:
            response_text = f"HTTP Error {status_code}: {resp.text}"
    except Exception as e:
        latency = round(time.time() - start_t, 2)
        status_code = 500
        response_text = f"Không thể kết nối Proxy: {str(e)}"

    verdict, reason = evaluate_full_cycle(
        category_code=category,
        prompt=active_prompt,
        response_text=response_text,
        status_code=status_code,
        secret=SECRET_KEY,
        model_name=judge_model
    )

    if status_code not in (200, 403) or not response_text.strip():
        verdict = "ERROR"
        reason = f"Lỗi phản hồi HTTP {status_code}"

    if verdict == "FAIL":
        try:
            save_or_update_threat_intel(
                attack_payload=active_prompt,
                vector_type=test_name,
                owasp_category=category,
                detected_source="RED_TEAM",
                detector_rule="Red Team Multi-threaded Scanner",
                tactics_desc=f"Kịch bản [{test_id}] vượt qua tường lửa thành công."
            )
        except Exception: pass

    save_result(
        model=target_model,
        test_id=test_id,
        category=category,
        name=test_name,
        prompt=active_prompt,
        response=response_text,
        status=verdict,
        reason=reason
    )

    return {
        "Mã ID": test_id,
        "Danh mục OWASP": category.split(":")[0].strip(),
        "Tên Kịch Bản": test_name,
        "Trạng thái": verdict,
        "Độ trễ": f"{latency}s",
        "Lý do Thẩm định": reason,
        "Phản hồi AI": response_text[:120] + "..." if len(response_text) > 120 else response_text
    }

if start_btn:
    if not chosen_tests:
        st.warning("⚠️ Vui lòng chọn ít nhất một kịch bản kiểm thử!")
    else:
        st.markdown("### 🚀 Tiến trình Thực thi Quét Đa Luồng")
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        results_list = []
        total_tests = len(chosen_tests)
        completed = 0
        
        scan_start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_test = {executor.submit(run_single_audit_task, item): item for item in chosen_tests}
            for future in as_completed(future_to_test):
                res = future.result()
                results_list.append(res)
                completed += 1
                progress_bar.progress(completed / total_tests)
                status_text.markdown(f"⚡ Đã hoàn thành: **{completed}/{total_tests}** kịch bản ({max_workers} luồng)...")
        
        total_scan_time = round(time.time() - scan_start_time, 2)
        status_text.markdown(f"✅ **Đã hoàn thành toàn bộ kịch bản trong {total_scan_time}s!**")
        st.balloons()

        count_blocked = sum(1 for r in results_list if r["Trạng thái"] == "BLOCKED")
        count_fail = sum(1 for r in results_list if r["Trạng thái"] == "FAIL")
        count_pass = sum(1 for r in results_list if r["Trạng thái"] == "PASS")
        count_error = sum(1 for r in results_list if r["Trạng thái"] == "ERROR")

        st.write("### 📊 Tổng kết Lượt Chạy")
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("TỔNG KỊCH BẢN", f"{total_tests}", f"Thời gian: {total_scan_time}s")
        m2.metric("TƯỜNG LỬA CHẶN (BLOCKED)", f"{count_blocked}", delta="Phòng thủ vòng ngoài", delta_color="normal")
        m3.metric("BỊ KHAI THÁC (FAIL)", f"{count_fail}", delta=f"-{count_fail} Lỗ hổng", delta_color="inverse")
        m4.metric("AN TOÀN / TỪ CHỐI (PASS)", f"{count_pass}", delta="Mô hình tự vệ", delta_color="normal")
        m5.metric("LỖI HỆ THỐNG (ERROR)", f"{count_error}", delta="Cần kiểm tra lại", delta_color="off")

        st.divider()

        st.write("### 📋 Bảng Chi Tiết Kết Quả Kiểm Thử (Audit Log)")
        df_res = pd.DataFrame(results_list)
        st.dataframe(
            df_res,
            column_config={
                "Trạng thái": st.column_config.SelectboxColumn("Trạng thái", options=["BLOCKED", "FAIL", "PASS", "ERROR"], required=True),
                "Mã ID": st.column_config.TextColumn("Mã ID", width="small"),
                "Danh mục OWASP": st.column_config.TextColumn("Nhóm OWASP", width="medium"),
                "Tên Kịch Bản": st.column_config.TextColumn("Tên ca kiểm thử", width="medium"),
                "Độ trễ": st.column_config.TextColumn("Thời gian", width="small"),
                "Lý do Thẩm định": st.column_config.TextColumn("Giải thích an ninh", width="large"),
                "Phản hồi AI": st.column_config.TextColumn("Nội dung AI trả về", width="large")
            },
            use_container_width=True,
            hide_index=True
        )

        csv_data = df_res.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ TẢI BÁO CÁO AUDIT (.CSV)",
            csv_data,
            "red_team_audit_report.csv",
            "text/csv",
            use_container_width=True
        )