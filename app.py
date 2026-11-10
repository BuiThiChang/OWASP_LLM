"""
FILE: app.py
Mô tả: Trang chủ Cổng Quản lý Dân cư & An toàn LLM Cấp Xã (Xã Tân Tiến).
- Tích hợp Đăng nhập & Phân quyền 3 cấp (Trưởng Công an Xã / Cán bộ CSKV / Công dân).
- Thống kê toàn diện 4 trạng thái kiểm thử OWASP 2026 và Tổng quan Dân cư cấp Xã.
- Điều hướng phân quyền trực quan đến các phân hệ chuyên sâu.
"""

import streamlit as st
import pandas as pd
import os

from db_manager import get_recent_logs, clear_all_logs, get_commune_residents
from auth_manager import (
    get_current_user,
    render_login_component,
    render_user_sidebar,
    is_logged_in,
    ROLE_ADMIN,
    ROLE_OFFICER,
    ROLE_CITIZEN,
    ROLE_LABELS
)

# 1. Cấu hình trang
st.set_page_config(
    page_title="Quản lý Dân cư & An toàn AI Cấp Xã - OWASP 2026",
    page_icon="🏛️",
    layout="wide"
)

# 2. Custom Cyber & Administrative CSS
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

# 3. KIỂM TRA ĐĂNG NHẬP
if not is_logged_in():
    render_login_component()
    st.stop()

# 4. Khi đã đăng nhập: Hiển thị Sidebar
render_user_sidebar()
current_user = get_current_user()
user_role = current_user.get("role", ROLE_CITIZEN)

with st.sidebar:
    st.markdown("### ⚙️ **Quản trị Địa bàn**")
    st.caption("Địa bàn: Xã Tân Tiến, Huyện An Dương")
    st.caption("CSDL: PostgreSQL (`commune_residents`)")
    st.divider()
    
    # Chỉ Admin mới có quyền xóa CSDL
    if user_role == ROLE_ADMIN:
        if st.button("🗑️ Xóa toàn bộ CSDL Kiểm thử", type="primary", use_container_width=True):
            success, msg = clear_all_logs()
            if success:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)
    else:
        st.info("🔒 Thao tác xóa CSDL chỉ dành cho Trưởng Công an Xã.")

# 5. Tiêu đề chính
st.title("🏛️ HỆ THỐNG QUẢN LÝ DÂN CƯ & AN TOÀN AI ĐỊA BÀN XÃ TÂN TIẾN")
st.caption(f"Xin chào **{current_user['full_name']}** ({ROLE_LABELS.get(user_role, user_role)}) | Cổng Tường lửa AI: Port 11435 | Chuẩn kiểm thử an ninh: OWASP 2026")

st.write("")

# 6. ĐIỀU HƯỚNG GIAO DIỆN THEO PHÂN QUYỀN

# --- 6A. GIAO DIỆN DÀNH CHO CÔNG DÂN ---
if user_role == ROLE_CITIZEN:
    st.markdown("""
    <div style="background-color: rgba(52, 211, 153, 0.05); border: 1px solid rgba(52, 211, 153, 0.3); border-radius: 12px; padding: 22px; margin-bottom: 25px;">
        <h3 style="color: #34d399; margin-top: 0;">👋 Chào mừng Công dân đến với Cổng Dịch vụ công Cư trú Xã Tân Tiến</h3>
        <p style="font-size: 0.95rem; margin-bottom: 15px;">
            Hệ thống Trợ lý AI Dịch vụ công hỗ trợ người dân tra cứu nhanh thủ tục đăng ký thường trú, tạm trú, 
            tách hộ, cấp thẻ Căn cước lưu động tại thôn và kích hoạt tài khoản định danh điện tử VNeID.
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    col_c1, col_c2 = st.columns([2, 1])
    with col_c1:
        st.markdown("""
        <div class="module-card" style="border-left: 4px solid #38bdf8;">
            <h4 style="color: #38bdf8; margin: 0 0 8px 0;">💬 Trợ lý AI Tư vấn Thủ tục Cư trú & Dịch vụ công Cấp Xã</h4>
            <p style="font-size: 0.9rem; opacity: 0.85;">
                Tương tác trực tiếp với Trợ lý AI để được hướng dẫn hồ sơ, biểu mẫu CT01, thời hạn giải quyết và địa điểm nộp hồ sơ tại Công an Xã Tân Tiến.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Truy cập Trợ lý Dịch vụ công Cư trú ➔", type="primary", use_container_width=True):
            st.switch_page("pages/2_🧪_Live_Sandbox.py")
            
    with col_c2:
        st.markdown("""
        <div style="background-color: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 18px;">
            <h5 style="margin-top: 0; color: #fbbf24;">🛡️ Chính sách Bảo vệ Dữ liệu</h5>
            <p style="font-size: 0.85rem; opacity: 0.8;">
                Theo quy định bảo vệ dữ liệu cá nhân, hệ thống được bảo vệ bởi Tường lửa AI Guardrail (Cổng 11435). Mọi yêu cầu trích xuất dữ liệu của người khác đều bị từ chối tuyệt đối.
            </p>
        </div>
        """, unsafe_allow_html=True)

# --- 6B. GIAO DIỆN DÀNH CHO CÁN BỘ & QUẢN TRỊ VIÊN ---
else:
    # Đọc logs và tính toán KPI Metrics chuẩn 4 trạng thái
    logs_data = get_recent_logs(1000)
    total_tests = len(logs_data)

    pass_count = sum(1 for row in logs_data if len(row) > 8 and str(row[8]).upper() in ['SAFE', 'PASS'])
    blocked_count = sum(1 for row in logs_data if len(row) > 8 and str(row[8]).upper() in ['BLOCKED', 'PROXY-BLOCKED'])
    fail_count = sum(1 for row in logs_data if len(row) > 8 and str(row[8]).upper() in ['FAIL', 'FAILED', 'EXPLOITED'])
    error_count = sum(1 for row in logs_data if len(row) > 8 and str(row[8]).upper() == 'ERROR')

    # Thống kê nhanh dữ liệu cư dân cấp xã
    residents_data = get_commune_residents(100)
    total_residents = len(residents_data)

    st.markdown('<div class="metrics-container">', unsafe_allow_html=True)
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    with m1:
        st.markdown(f'<div class="metric-card"><div class="metric-title">NHÂN KHẨU XÃ</div><div class="metric-value" style="color: #38bdf8;">{total_residents}</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="metric-card"><div class="metric-title">TỔNG KIỂM THỬ</div><div class="metric-value">{total_tests}</div></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #4ade80;">AN TOÀN (PASS)</div><div class="metric-value" style="color: #4ade80;">{pass_count}</div></div>', unsafe_allow_html=True)
    with m4:
        st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #fbbf24;">CHẶN (BLOCKED)</div><div class="metric-value" style="color: #fbbf24;">{blocked_count}</div></div>', unsafe_allow_html=True)
    with m5:
        st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #f87171;">BỊ LỘ (FAIL)</div><div class="metric-value" style="color: #f87171;">{fail_count}</div></div>', unsafe_allow_html=True)
    with m6:
        st.markdown(f'<div class="metric-card"><div class="metric-title" style="color: #94a3b8;">LỖI (ERROR)</div><div class="metric-value" style="color: #94a3b8;">{error_count}</div></div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    # Các Phân Hệ Nghiệp Vụ Chính
    st.subheader("🚀 Các Phân Hệ Nghiệp Vụ & An Ninh Cấp Xã")
    st.caption("💡 Lựa chọn phân hệ nghiệp vụ phù hợp với thẩm quyền công tác của cán bộ:")

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

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("""
        <div class="module-card" style="border-left: 4px solid #f43f5e; min-height: 140px;">
            <h4 style="color: #f43f5e; margin: 0 0 8px 0;">🔴 Module 1: Red Team Audit Dân Cư</h4>
            <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">Quét tự động kịch bản khai thác an ninh quản lý dân cư xã theo 10 nhóm nguy cơ OWASP 2026 (A01 -> A10).</p>
        </div>
        """, unsafe_allow_html=True)
        if user_role == ROLE_ADMIN:
            if st.button("Truy cập Red Team Audit ↗", key="btn_go_mod1", use_container_width=True):
                st.switch_page(page_mod1)
        else:
            st.button("🔒 Yêu cầu quyền Trưởng Công an Xã", disabled=True, key="btn_dis_mod1", use_container_width=True)

    with c2:
        st.markdown("""
        <div class="module-card" style="border-left: 4px solid #38bdf8; min-height: 140px;">
            <h4 style="color: #38bdf8; margin: 0 0 8px 0;">🧪 Module 2: Live Sandbox & Tra Cứu Cư Trú</h4>
            <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">Tương tác đối chứng trực tiếp: Có Tường lửa Proxy 11435 vs Mô hình hở 11436, tích hợp RAG nhân khẩu xã.</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Truy cập Live Sandbox ↗", key="btn_go_mod2", use_container_width=True):
            st.switch_page(page_mod2)

    st.write("")

    c3, c4 = st.columns(2)

    with c3:
        st.markdown("""
        <div class="module-card" style="border-left: 4px solid #34d399; min-height: 140px;">
            <h4 style="color: #34d399; margin: 0 0 8px 0;">📊 Module 3: SOC Monitor Giám Sát Địa Bàn</h4>
            <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">Trung tâm giám sát an ninh: Trực quan hóa nguy cơ rò rỉ PII cư dân, lọc sự cố và xuất nhật ký kiểm toán CSV.</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Truy cập SOC Monitor ↗", key="btn_go_mod3", use_container_width=True):
            st.switch_page(page_mod3)

    with c4:
        st.markdown("""
        <div class="module-card" style="border-left: 4px solid #a855f7; min-height: 140px;">
            <h4 style="color: #c084fc; margin: 0 0 8px 0;">🛡️ Module 4: Threat Intelligence Cấp Xã</h4>
            <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">Kho tri thức nguy cơ: Lưu trữ và tra cứu chữ ký SHA-256 các mẫu payload tấn công vào hệ thống dân cư xã.</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Truy cập Threat Intelligence ↗", key="btn_go_mod4", use_container_width=True):
            st.switch_page(page_mod4)

    st.write("")

    c5, _ = st.columns([1, 1])
    with c5:
        st.markdown("""
        <div class="module-card" style="border-left: 4px solid #00f3ff; min-height: 140px;">
            <h4 style="color: #00f3ff; margin: 0 0 8px 0;">⚖️ Module 5: A/B Benchmark & Mitigation</h4>
            <p style="font-size: 0.88rem; opacity: 0.85; margin: 0;">Kiểm thử hiệu năng an ninh đối chứng: Đo đạc tỷ lệ chặn, rò rỉ dữ liệu và độ trễ phản hồi giữa Port 11435 và 11436.</p>
        </div>
        """, unsafe_allow_html=True)
        if user_role == ROLE_ADMIN:
            if st.button("Truy cập A/B Benchmark ↗", key="btn_go_mod5", use_container_width=True):
                st.switch_page(page_mod5)
        else:
            st.button("🔒 Yêu cầu quyền Trưởng Công an Xã", disabled=True, key="btn_dis_mod5", use_container_width=True)
