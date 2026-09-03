import streamlit as st
import pandas as pd
from pages.db_manager import get_recent_logs
import os

# 1. Cấu hình Trang
st.set_page_config(
    page_title="LLMVault Security Suite & OWASP AI Guardrail",
    page_icon="🛡️",
    layout="wide"
)

# ==============================================================================
# 🔀 BỘ ĐIỀU HƯỚNG SPA (CHẠY TRỰC TIẾP CODE MODULE BẰNG EXEC)
# ==============================================================================
query_params = st.query_params

if "page" in query_params:
    page_target = query_params["page"]
    
    # Xác định file module tương ứng
    file_map = {
        "red_team": "pages/1_red_team_audit.py",
        "live_sandbox": "pages/2_live_sandbox.py",
        "soc_monitor": "pages/3_soc_monitor.py"
    }
    
    target_file = file_map.get(page_target)
    
    if target_file and os.path.exists(target_file):
        # Nạp và thực thi code của trang con ngay tại đây
        with open(target_file, "r", encoding="utf-8") as f:
            code = f.read()
        exec(code, globals())
        st.stop() # Dừng không cho nạp trang chủ app.py bên dưới nữa

# ==============================================================================
# 🎨 GIAO DIỆN TRANG CHỦ DASHBOARD (HIỂN THỊ KHI TRUY CẬP LOCALHOST:8501)
# ==============================================================================

# Custom CSS cho Khung Metrics và Module Cards
st.markdown("""
<style>
    .stAppDeployButton, button[title="Deploy this app"], [data-testid="stAppDeployButton"], footer {
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
        padding: 22px;
        height: 100%;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        background-color: rgba(255, 255, 255, 0.02);
        transition: all 0.2s ease-in-out;
    }
    .module-title {
        font-size: 1.2rem;
        font-weight: 700;
        margin-bottom: 12px;
    }
    .module-desc {
        font-size: 0.88rem;
        opacity: 0.82;
        line-height: 1.5;
        margin-bottom: 20px;
        min-height: 55px;
    }
    .open-tab-btn {
        display: block;
        width: 100%;
        text-align: center;
        padding: 10px 14px;
        border-radius: 8px;
        text-decoration: none !important;
        font-weight: 600;
        font-size: 0.88rem;
    }
    .mod-1 { border: 1px solid rgba(244, 63, 94, 0.4); }
    .mod-1 .module-title { color: #f43f5e; }
    .btn-1 { background-color: #e11d48; color: #ffffff !important; }

    .mod-2 { border: 1px solid rgba(6, 182, 212, 0.4); }
    .mod-2 .module-title { color: #38bdf8; }
    .btn-2 { background-color: #0284c7; color: #ffffff !important; }

    .mod-3 { border: 1px solid rgba(16, 185, 129, 0.4); }
    .mod-3 .module-title { color: #34d399; }
    .btn-3 { background-color: #059669; color: #ffffff !important; }
</style>
""", unsafe_allow_html=True)

# Header
st.title("🛡️ LLMVault Security Suite & OWASP AI Guardrail")
st.caption("Nền tảng tổng hợp Đánh giá lỗ hổng LLM (Red Teaming), Phòng thủ theo thời gian thực (AI Proxy Firewall) & Giám sát An ninh (SOC Monitor)")

st.write("")

# Metrics
logs_data = get_recent_logs(1000)
total_tests = len(logs_data)
pass_tests = sum(1 for row in logs_data if len(row) > 8 and row[8] == 'PASS')
fail_tests = sum(1 for row in logs_data if len(row) > 8 and row[8] == 'FAIL')
blocked_tests = sum(1 for row in logs_data if len(row) > 8 and row[8] == 'BLOCKED')

st.markdown('<div class="metrics-container">', unsafe_allow_html=True)
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(f'<div class="metric-card"><div class="metric-title">TỔNG KỊCH BẢN TEST</div><div class="metric-value">{total_tests}</div></div>', unsafe_allow_html=True)
with m2:
    st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #4ade80;">AN TOÀN (PASS)</div><div class="metric-value" style="color: #4ade80;">{pass_tests}</div></div>', unsafe_allow_html=True)
with m3:
    st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #f87171;">CÓ LỖ HỒNG (FAIL)</div><div class="metric-value" style="color: #f87171;">{fail_tests}</div></div>', unsafe_allow_html=True)
with m4:
    st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #fbbf24;">FIREWALL ĐÃ CHẮN</div><div class="metric-value" style="color: #fbbf24;">{blocked_tests}</div></div>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)

st.subheader("🚀 Chọn Module Ứng Dụng Xử Lý")

# 3 Khung Module có liên kết URL Query Param mở Tab Chrome mới
c1, c2, c3 = st.columns(3)

with c1:
    st.markdown("""
    <div class="module-card mod-1">
        <div>
            <div class="module-title">🎯 Module 1: Red Team Audit</div>
            <div class="module-desc">Tự động quét & khai thác 17+ lỗ hổng OWASP Top 10 đối với LLM (Prompt Injection, System Leak, Context Poisoning...).</div>
        </div>
        <a href="/?page=red_team" target="_blank" class="open-tab-btn btn-1">⚡ MỞ MODULE 1 (TAB MỚI) ↗</a>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown("""
    <div class="module-card mod-2">
        <div>
            <div class="module-title">💬 Module 2: Live AI Firewall</div>
            <div class="module-desc">Sandbox tương tác trực tiếp qua cổng AI Guardrail Proxy (Port 11435) để thử nghiệm chặn câu lệnh độc hại thời gian thực.</div>
        </div>
        <a href="/?page=live_sandbox" target="_blank" class="open-tab-btn btn-2">🛡️ MỞ MODULE 2 (TAB MỚI) ↗</a>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown("""
    <div class="module-card mod-3">
        <div>
            <div class="module-title">📊 Module 3: SOC Monitor</div>
            <div class="module-desc">Trung tâm giám sát nhật ký an ninh, truy vết dữ liệu sự cố và thống kê các lượt truy cập vi phạm theo quy chuẩn audit.</div>
        </div>
        <a href="/?page=soc_monitor" target="_blank" class="open-tab-btn btn-3">📊 MỞ MODULE 3 (TAB MỚI) ↗</a>
    </div>
    """, unsafe_allow_html=True)