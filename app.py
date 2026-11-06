"""
FILE: app.py
Mô tả: Trang chủ Dashboard Trung tâm - LLMVault Security Suite & OWASP AI Guardrail.
- Thống kê toàn diện 4 trạng thái: SAFE/PASS | BLOCKED | FAIL | ERROR
- Tích hợp nút xóa sạch dữ liệu PostgreSQL tập trung trên Sidebar
- Điều hướng trực quan đến 5 phân hệ chuyên sâu
"""

import streamlit as st
import pandas as pd
import os

from db_manager import get_recent_logs, clear_all_logs

# 1. Cấu hình trang
st.set_page_config(
    page_title="LLMVault Security Suite & OWASP 2026",
    page_icon="🛡️",
    layout="wide"
)

# 2. Sidebar điều khiển
with st.sidebar:
    st.markdown("### ⚙️ **Quản trị Hệ thống**")
    st.caption("Cơ sở dữ liệu: PostgreSQL (llmvault_db)")
    st.divider()
    if st.button("🗑️ Xóa toàn bộ CSDL PostgreSQL", type="primary", use_container_width=True):
        success, msg = clear_all_logs()
        if success:
            st.success(msg)
            st.rerun()
        else:
            st.error(msg)

# 3. Custom Cyber CSS
st.markdown("""
<style>
    .stAppDeployButton, button[title="Deploy this app"], footer {
        display: none !important;
    }
    .metrics-container {
        border: 1px solid rgba(128, 128, 128, 0.25);
        background-color: rgba(255, 255, 255, 0.015);
        border-radius: 12px;
        padding: 16px 20px;
        margin-bottom: 25px;
    }
    .metric-card {
        background-color: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(128, 128, 128, 0.2);
        border-radius: 8px;
        padding: 12px 16px;
        text-align: center;
    }
    .metric-title {
        font-size: 0.8rem;
        font-weight: 600;
        opacity: 0.75;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        margin-bottom: 6px;
    }
    .metric-value {
        font-size: 1.8rem;
        font-weight: 700;
        font-family: monospace;
    }
    .module-card {
        border-radius: 12px;
        padding: 20px;
        background-color: rgba(255, 255, 255, 0.02);
        border: 1px solid rgba(255, 255, 255, 0.1);
        margin-bottom: 15px;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ LLMVault Security Suite & OWASP AI Guardrail")
st.caption("Nền tảng kiểm thử an ninh LLM theo chuẩn OWASP 2026 (A01 -> A10), Tường lửa AI Proxy (Port 11435) & SOC Monitor")

st.write("")

# 4. Đọc logs và tính toán KPI Metrics chuẩn 4 trạng thái
logs_data = get_recent_logs(1000)
total_tests = len(logs_data)

pass_count = sum(1 for row in logs_data if len(row) > 8 and str(row[8]).upper() in ['SAFE', 'PASS'])
blocked_count = sum(1 for row in logs_data if len(row) > 8 and str(row[8]).upper() in ['BLOCKED', 'PROXY-BLOCKED'])
fail_count = sum(1 for row in logs_data if len(row) > 8 and str(row[8]).upper() in ['FAIL', 'FAILED', 'EXPLOITED'])
error_count = sum(1 for row in logs_data if len(row) > 8 and str(row[8]).upper() == 'ERROR')

st.markdown('<div class="metrics-container">', unsafe_allow_html=True)
m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    st.markdown(f'<div class="metric-card"><div class="metric-title">TỔNG TRUY VẤN</div><div class="metric-value">{total_tests}</div></div>', unsafe_allow_html=True)
with m2:
    st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #4ade80;">AN TOÀN (PASS)</div><div class="metric-value" style="color: #4ade80;">{pass_count}</div></div>', unsafe_allow_html=True)
with m3:
    st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #fbbf24;">TƯỜNG LỬA CHẶN (BLOCKED)</div><div class="metric-value" style="color: #fbbf24;">{blocked_count}</div></div>', unsafe_allow_html=True)
with m4:
    st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #f87171;">BỊ KHAI THÁC (FAIL)</div><div class="metric-value" style="color: #f87171;">{fail_count}</div></div>', unsafe_allow_html=True)
with m5:
    st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #94a3b8;">LỖI HỆ THỐNG (ERROR)</div><div class="metric-value" style="color: #94a3b8;">{error_count}</div></div>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)

# 5. Các Phân Hệ Nghiệp Vụ Chính
st.subheader("🚀 Các Phân Hệ Nghiệp Vụ Chính")
st.caption("💡 Bấm trực tiếp vào các nút bên dưới hoặc chọn tại thanh Sidebar bên trái để truy cập module:")

def get_actual_page_path(prefix: str, fallback_name: str) -> str:
    pages_dir = os.path.join(os.path.dirname(__file__), "pages")
    if os.path.exists(pages_dir):
        for f in os.listdir(pages_dir):
            if f.startswith(prefix) and f.endswith(".py"):
                return f"pages/{f}"
    return f"pages/{fallback_name}"

page_mod1 = get_actual_page_path("1_", "1_red_team_audit.py")
page_mod2 = get_actual_page_path("2_", "2_live_sandbox.py")
page_mod3 = get_actual_page_path("3_", "3_soc_monitor.py")
page_mod4 = get_actual_page_path("4_", "4_threat_intelligence.py")
page_mod5 = get_actual_page_path("5_", "5_ab_benchmark.py")

c1, c2, c3 = st.columns(3)

with c1:
    st.markdown("""
    <div class="module-card" style="border-left: 4px solid #f43f5e; min-height: 140px;">
        <h4 style="color: #f43f5e; margin: 0 0 8px 0;">🔴 Module 1: Red Team Audit</h4>
        <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">Quét tự động kịch bản khai thác 10 nhóm nguy cơ OWASP 2026 (A01 -> A10), đo lường mức độ an toàn.</p>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Truy cập Red Team Audit ↗", key="btn_go_mod1", use_container_width=True):
        st.switch_page(page_mod1)

with c2:
    st.markdown("""
    <div class="module-card" style="border-left: 4px solid #38bdf8; min-height: 140px;">
        <h4 style="color: #38bdf8; margin: 0 0 8px 0;">🧪 Module 2: Live Sandbox</h4>
        <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">Thử nghiệm thời gian thực: Tương tác trực tiếp qua cổng Tường lửa Proxy 11435 và quét tệp/ảnh OCR.</p>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Truy cập Live Sandbox ↗", key="btn_go_mod2", use_container_width=True):
        st.switch_page(page_mod2)

with c3:
    st.markdown("""
    <div class="module-card" style="border-left: 4px solid #34d399; min-height: 140px;">
        <h4 style="color: #34d399; margin: 0 0 8px 0;">📊 Module 3: SOC Monitor</h4>
        <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">Trung tâm điều hành an ninh mạng: Trực quan hóa ma trận rủi ro qua Radar, lọc sự cố và xuất báo cáo CSV.</p>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Truy cập SOC Monitor ↗", key="btn_go_mod3", use_container_width=True):
        st.switch_page(page_mod3)

st.write("")

c4, c5 = st.columns(2)

with c4:
    st.markdown("""
    <div class="module-card" style="border-left: 4px solid #a855f7; min-height: 130px;">
        <h4 style="color: #c084fc; margin: 0 0 8px 0;">🛡️ Module 4: Threat Intelligence</h4>
        <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">Kho tri thức nguy cơ: Lưu trữ và tra cứu chữ ký số SHA-256 các mẫu payload tấn công từ Red Team & Blue Team.</p>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Truy cập Threat Intelligence ↗", key="btn_go_mod4", use_container_width=True):
        st.switch_page(page_mod4)

with c5:
    st.markdown("""
    <div class="module-card" style="border-left: 4px solid #00f3ff; min-height: 130px;">
        <h4 style="color: #00f3ff; margin: 0 0 8px 0;">⚖️ Module 5: A/B Benchmark</h4>
        <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">Đánh giá định lượng hiệu quả bảo vệ: So sánh đối chứng trực tiếp giữa mô hình nguyên bản và mô hình có Tường lửa.</p>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Truy cập A/B Benchmark ↗", key="btn_go_mod5", use_container_width=True):
        st.switch_page(page_mod5)