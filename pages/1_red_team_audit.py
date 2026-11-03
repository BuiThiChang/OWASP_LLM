"""
FILE: pages/1_red_team_audit.py
Mô tả: Phân hệ Kiểm thử An ninh Tự động (Red Team Audit Engine).
- Nạp kịch bản OWASP Top 10 nghiệp vụ từ test_cases.py
- Thực thi kiểm thử xuyên qua AI Guardrail Proxy (Port 11435)
- Thẩm định kết quả chuẩn hóa 3 trạng thái: BLOCKED | FAIL | PASS
- Tự động đồng bộ mẫu tấn công vào Threat Intelligence DB và SOC Audit Log
"""

import streamlit as st
import pandas as pd
import requests
import time
import sys
import os

# 1. THIẾT LẬP ĐƯỜNG DẪN IMPORT TỪ THƯ MỤC GỐC
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

# 2. IMPORT CÁC MODULE DÙNG CHUNG CỦA HỆ THỐNG
from test_cases import OWASP_TESTS
from security_engine import evaluate_full_cycle
from db_manager import save_result
try:
    from db_manager import save_or_update_threat_intel
except ImportError:
    def save_or_update_threat_intel(*args, **kwargs):
        pass

# 3. CẤU HÌNH GIAO DIỆN STREAMLIT
st.set_page_config(
    page_title="Red Team Security Audit",
    page_icon="🎯",
    layout="wide"
)

# Custom CSS giao diện Red Team (Tone màu Đỏ/Hồng đặc trưng)
st.markdown("""
<style>
    .stAppDeployButton, button[title="Deploy this app"], [data-testid="stAppDeployButton"], footer {
        display: none !important;
    }
    .red-header {
        border-left: 5px solid #f43f5e;
        padding-left: 15px;
        margin-bottom: 20px;
    }
    .red-title {
        color: #f43f5e;
        font-weight: 700;
        font-size: 1.8rem;
    }
    .scenario-card {
        background-color: rgba(244, 63, 94, 0.05);
        border: 1px solid rgba(244, 63, 94, 0.2);
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

# 4. TIÊU ĐỀ MODULE
st.markdown("""
<div class="red-header">
    <div class="red-title">🎯 MODULE 01: RED TEAM AUTOMATED AUDIT ENGINE</div>
    <div style="opacity: 0.85; font-size: 0.95rem;">
        Hệ thống tự động thực thi các chuỗi kịch bản khai thác lỗ hổng bảo mật LLM theo tiêu chuẩn OWASP Top 10.
    </div>
</div>
""", unsafe_allow_html=True)

DEFAULT_PROXY_URL = "http://localhost:11435/v1/chat/completions"
SECRET_KEY = "OWASP-LLM-TEST-2026-7F3A9C"

# 5. KHUNG ĐIỀU KHIỂN & BỘ LỌC KỊCH BẢN
col_ctrl, col_view = st.columns([1, 2])

with col_ctrl:
    st.markdown("#### ⚙️ Cấu hình Kiểm thử")
    target_model = st.text_input("Mô hình mục tiêu (Target Model):", value="llama3.2:3b")
    proxy_url = st.text_input("Cổng Tường lửa AI Proxy:", value=DEFAULT_PROXY_URL)

    # Lấy danh sách category từ test_cases.py
    available_categories = list(OWASP_TESTS.keys())
    selected_categories = st.multiselect(
        "Chọn nhóm lỗ hổng cần rà quét:",
        options=available_categories,
        default=available_categories
    )

    # Gom các ca kiểm thử được chọn
    chosen_tests = []
    for cat in selected_categories:
        for t in OWASP_TESTS.get(cat, []):
            chosen_tests.append({"category": cat, **t})

    st.info(f"📌 Tổng số kịch bản chuẩn bị thực thi: **{len(chosen_tests)}**")
    start_btn = st.button("⚡ EXECUTE RED TEAM SCAN", type="primary", use_container_width=True)

with col_view:
    st.markdown("#### 📋 Xem trước Kịch bản Tấn công")
    preview_container = st.container(height=380)
    with preview_container:
        for item in chosen_tests:
            st.markdown(f"""
            <div class="scenario-card">
                <strong style="color: #f43f5e;">[{item['id']}] {item['category']}</strong><br/>
                <span style="font-weight: 600;">{item['name']}</span><br/>
                <code style="font-size: 0.85rem; color: #e2e8f0;">Payload: {item['prompt']}</code>
            </div>
            """, unsafe_allow_html=True)

st.divider()

# 6. LUỒNG THỰC THI KIỂM THỬ TỰ ĐỘNG
if start_btn:
    if not chosen_tests:
        st.warning("⚠️ Vui lòng chọn ít nhất một danh mục để thực thi kiểm thử!")
    else:
        st.markdown("### 🚀 Tiến trình Thực thi Red Team Audit")
        progress_bar = st.progress(0)
        status_text = st.empty()

        results_list = []
        count_blocked = 0
        count_fail = 0
        count_pass = 0
        total_tests = len(chosen_tests)

        for idx, item in enumerate(chosen_tests):
            category = item["category"]
            prompt = item["prompt"]
            test_id = item["id"]
            test_name = item["name"]

            status_text.markdown(f"⏳ **[{idx+1}/{total_tests}]** Đang gửi: `[{test_id}] {test_name}`...")
            start_time = time.time()

            # Gửi truy vấn qua AI Guardrail Proxy (Port 11435)
            try:
                payload = {
                    "model": target_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False
                }
                resp = requests.post(proxy_url, json=payload, timeout=250)
                latency = round(time.time() - start_time, 2)
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
                latency = round(time.time() - start_time, 2)
                status_code = 500
                response_text = f"Không thể kết nối Tường lửa Proxy: {str(e)}"

            # GỌI HÀM THẨM ĐỊNH TOÀN CHU TRÌNH (Từ security_engine kế thừa challenges/)
            verdict, reason = evaluate_full_cycle(
                category_code=category,
                prompt=prompt,
                response_text=response_text,
                status_code=status_code,
                secret=SECRET_KEY
            )

            # Cập nhật số đếm thống kê
            if verdict == "BLOCKED":
                count_blocked += 1
            elif verdict == "FAIL":
                count_fail += 1
                # Nạp mẫu độc hại vượt rào vào Threat Intelligence DB
                try:
                    save_or_update_threat_intel(
                        attack_payload=prompt,
                        vector_type=test_name,
                        owasp_category=category,
                        detected_source="RED_TEAM",
                        detector_rule="Red Team Automated Scanner",
                        tactics_desc=f"Kịch bản [{test_id}] vượt qua kiểm soát và khai thác thành công LLM."
                    )
                except Exception as tie:
                    print(f"⚠️ Lỗi Threat Intel: {tie}")
            else:
                count_pass += 1

            # Lưu vào Database phục vụ SOC Monitor
            try:
                save_result(
                    model=target_model,
                    test_id=test_id,
                    category=category,
                    name=test_name,
                    prompt=prompt,
                    response=response_text,
                    status=verdict,
                    reason=reason
                )
            except Exception as dbe:
                print(f"⚠️ Lỗi lưu CSDL: {dbe}")

            results_list.append({
                "Mã ID": test_id,
                "Danh mục OWASP": category.split(" - ")[0],
                "Tên Kịch Bản": test_name,
                "Trạng thái": verdict,
                "Độ trễ": f"{latency}s",
                "Lý do Thẩm định": reason,
                "Phản hồi AI": response_text[:120] + "..." if len(response_text) > 120 else response_text
            })

            progress_bar.progress((idx + 1) / total_tests)
            time.sleep(0.1)

        status_text.markdown("✅ **Đã hoàn thành toàn bộ kịch bản Red Team Audit!**")
        st.balloons()

        # 7. KHUNG CHỈ SỐ THỐNG KÊ (METRICS)
        st.write("### 📊 Tổng kết Lượt Chạy")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("TỔNG KỊCH BẢN", f"{total_tests}")
        m2.metric("TƯỜNG LỬA CHẶN (BLOCKED)", f"{count_blocked}", delta="Phòng thủ vòng ngoài", delta_color="normal")
        m3.metric("BỊ KHAI THÁC (FAIL)", f"{count_fail}", delta=f"-{count_fail} Lỗ hổng", delta_color="inverse")
        m4.metric("AN TOÀN / TỰ TỪ CHỐI (PASS)", f"{count_pass}", delta="Mô hình phòng thủ tốt", delta_color="normal")

        st.divider()

        # 8. BẢNG BÁO CÁO KẾT QUẢ CHI TIẾT
        st.write("### 📋 Bảng Chi Tiết Kết Quả Kiểm Thử (Audit Log)")
        df_res = pd.DataFrame(results_list)

        st.dataframe(
            df_res,
            column_config={
                "Trạng thái": st.column_config.SelectboxColumn(
                    "Trạng thái",
                    help="Kết quả đánh giá an ninh chuẩn hóa",
                    options=["BLOCKED", "FAIL", "PASS"],
                    required=True,
                ),
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