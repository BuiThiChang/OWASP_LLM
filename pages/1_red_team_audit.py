import streamlit as st
import pandas as pd
import time
import importlib
import sys
import os
from db_manager import save_result, save_or_update_threat_intel  # Thêm save_or_update_threat_intel

# Thêm thư mục gốc vào path để import db_manager và test_cases
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from db_manager import save_result
from test_cases import LAB_SUITE  # <-- Import dữ liệu từ test_cases.py

st.set_page_config(page_title="Red Team Audit", page_icon="🎯", layout="wide")

st.title("🎯 Module 1: Red Team Automated Security Audit")
st.caption("Chế độ kiểm thử tự động hàng loạt (Batch Scan) trên toàn bộ 10 bài lab OWASP LLM và đánh giá hiệu năng phòng thủ.")

st.sidebar.header("⚙️ Cấu Hình Audit")
scan_mode = st.sidebar.radio(
    "Chọn kịch bản Audit:",
    ["🔥 Tấn công toàn bộ 10 Bài Lab (Red Team Attack)", "🛡️ Kiểm thử An toàn (Safe Benchmark Baseline)", "🎯 Chọn thủ công 1 Lab"]
)

selected_target_id = None
if scan_mode == "🎯 Chọn thủ công 1 Lab":
    selected_target_id = st.sidebar.selectbox("Chọn Lab:", [item["id"] + " - " + item["name"] for item in LAB_SUITE]).split(" - ")[0]

if st.button("🚀 BẮT ĐẦU CHẠY AUDIT HÀNG LOẠT", type="primary"):
    st.write("---")
    
    targets = [item for item in LAB_SUITE if item["id"] == selected_target_id] if scan_mode == "🎯 Chọn thủ công 1 Lab" else LAB_SUITE

    results_data = []
    progress_bar = st.progress(0)
    status_text = st.empty()
    total_targets = len(targets)
    
    for idx, item in enumerate(targets):
        status_text.text(f"⏳ Đang kiểm thử [{idx+1}/{total_targets}]: {item['id']} - {item['name']}...")
        payload = item["safe_prompt"] if "Safe Benchmark" in scan_mode else item["attack_prompt"]
        
        try:
            mod = importlib.import_module(item["module"])
            response = mod.process_message(payload) if hasattr(mod, "process_message") else "⚠️ Lab thiếu hàm process_message"
        except Exception as e:
            response = f"⚠️ Lỗi thực thi: {str(e)}"
            
        response_str = str(response)
        
        if "FLAG{" in response_str:
            status, badge, reason = "BLOCKED", "❌ EXPLOIT", "Vulnerability exploited successfully."
            
            # 🌟 [BỔ SUNG BƯỚC 3]: Nếu bẻ khóa/khai thác thành công, lưu vào CSDL Tri thức nguy cơ
            try:
                save_or_update_threat_intel(
                    attack_payload=payload,
                    vector_type=item["name"],
                    owasp_category=item["id"],
                    detected_source="RED_TEAM",
                    detector_rule="Red Team Automated Scanner",
                    tactics_desc=f"Kịch bản rà quét {item['id']} vượt qua được mô hình LLM mục tiêu."
                )
            except Exception as e:
                print(f"Lỗi ghi Threat Intel từ Red Team: {e}")
        elif "⚠️" in response_str or "ERROR" in response_str.upper():
            status, badge, reason = "ERROR", "⚠️ LỖI", "Execution error encountered."
        else:
            status, badge, reason = "SAFE", "✅ DEFENDED", "System defended successfully."

        save_result("gpt-4-turbo", item["id"], item["name"], item["name"], payload, response_str, status, reason)

        results_data.append({
            "STT": idx + 1,
            "Mã Lab": item["id"],
            "Tên Kịch Bản": item["name"],
            "Chế Độ": "Safe Test" if "Safe Benchmark" in scan_mode else "Red Team Attack",
            "Payload Thử Nghiệm": payload[:60] + "..." if len(payload) > 60 else payload,
            "Phản Hồi Từ AI": response_str[:80] + "..." if len(response_str) > 80 else response_str,
            "Trạng Thái": status,
            "Kết Quả": badge
        })
        
        progress_bar.progress((idx + 1) / total_targets)
        time.sleep(0.2)
        
    status_text.success("🎉 Đã hoàn tất toàn bộ quá trình Audit và đồng bộ dữ liệu SOC!")

    df_results = pd.DataFrame(results_data)
    total_scanned = len(df_results)
    total_failed = sum(1 for r in results_data if r["Trạng Thái"] == "BLOCKED")
    total_passed = sum(1 for r in results_data if r["Trạng Thái"] == "SAFE")
    defense_rate = round((total_passed / total_scanned) * 100, 1) if total_scanned > 0 else 0

    st.write("### 📊 Thống Kê Tổng Quan Audit")
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("TỔNG SỐ LAB ĐÃ QUÉT", f"{total_scanned}")
    with m2: st.metric("AN TOÀN (DEFENDED)", f"{total_passed}", delta=f"{defense_rate}% Thành công")
    with m3: st.metric("BỊ KHAI THÁC (VULNERABLE)", f"{total_failed}", delta=f"-{total_failed}", delta_color="inverse")
    with m4: st.metric("TỶ LỆ PHÒNG THỦ", f"{defense_rate}%")

    st.write("---")
    st.dataframe(
    df_results[["STT", "Mã Lab", "Tên Kịch Bản", "Chế Độ", "Payload Thử Nghiệm", "Phản Hồi Từ AI", "Kết Quả"]],
    width="stretch",
    hide_index=True
)