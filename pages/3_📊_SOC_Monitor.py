"""
FILE: pages/3_soc_monitor.py
Mô tả: Module 03 - Trung tâm Giám sát An ninh (SOC Monitor & Audit Trail) Tối ưu hóa.
- Tích hợp Phân trang Pagination & Giới hạn bản ghi LIMIT chống lag trình duyệt
- Tự động làm mới dữ liệu thời gian thực và phân tích biểu đồ Radar/Pie chart
- Chuẩn hóa OWASP 2026 (A01 -> A10) và xử lý hiển thị thời gian chính xác
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sys
import os

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from db_manager import get_paginated_logs, get_recent_logs, clear_all_logs
from security_engine import normalize_to_owasp_2026
from auth_manager import require_auth, render_user_sidebar, ROLE_ADMIN, ROLE_OFFICER

st.set_page_config(
    page_title="SOC Security Monitor & Audit Trail",
    page_icon="📊",
    layout="wide"
)

# Chỉ Trưởng Công an Xã (Admin) và Cán bộ (Officer) mới được xem SOC Monitor
current_user = require_auth(allowed_roles=[ROLE_ADMIN, ROLE_OFFICER])
render_user_sidebar()

st.markdown("""
<style>
    .stAppDeployButton, button[title="Deploy this app"], footer { display: none !important; }
    .green-header { border-left: 5px solid #10b981; padding-left: 15px; margin-bottom: 20px; }
    .green-title { color: #34d399; font-weight: 700; font-size: 1.8rem; }
    .summary-card {
        background-color: rgba(16, 185, 129, 0.04);
        border: 1px solid rgba(16, 185, 129, 0.25);
        border-radius: 8px;
        padding: 14px 18px;
        text-align: center;
        box-shadow: 0 4px 12px rgba(0,0,0,0.25);
    }
    .card-title { font-size: 0.8rem; opacity: 0.8; font-weight: 600; text-transform: uppercase; }
    .card-num { font-size: 1.8rem; font-weight: 700; margin-top: 4px; font-family: monospace; }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="green-header">
    <div class="green-title">📊 MODULE 03: SOC SECURITY OPERATIONS CENTER & AUDIT TRAIL</div>
    <div style="opacity: 0.85; font-size: 0.95rem;">
        Trung tâm tiếp nhận sự kiện, phân tích nhật ký an ninh và giám sát khả năng phòng thủ theo thời gian thực (Chuẩn OWASP 2026).
    </div>
</div>
""", unsafe_allow_html=True)

# 1. BỘ ĐIỀU PHỐI & PHÂN TRANG SIDEBAR
with st.sidebar:
    st.markdown("### ⚙️ **Bộ lọc & Phân trang SOC**")
    status_filter = st.selectbox("Lọc theo Trạng thái:", options=["ALL", "BLOCKED", "FAIL", "PASS", "ERROR"], index=0)
    page_size = st.selectbox("Số bản ghi mỗi trang (LIMIT):", options=[25, 50, 100, 200], index=1)
    
    st.divider()
    if st.button("🔄 Làm mới dữ liệu (Refresh)", use_container_width=True):
        st.rerun()

    if st.button("🗑️ Xóa sạch CSDL Audit", type="primary", use_container_width=True):
        clear_all_logs()
        st.success("✅ Đã làm sạch toàn bộ CSDL!")
        st.rerun()

if "current_page" not in st.session_state:
    st.session_state.current_page = 1

# Lấy dữ liệu phân trang từ CSDL PostgreSQL
paginated_logs, total_records = get_paginated_logs(
    page=st.session_state.current_page,
    page_size=page_size,
    status_filter=status_filter
)

total_pages = max(1, (total_records + page_size - 1) // page_size)
if st.session_state.current_page > total_pages:
    st.session_state.current_page = total_pages

# 2. KHU VỰC THỐNG KÊ NHANH TỪ 1000 BẢN GHI GẦN NHẤT
all_recent = get_recent_logs(1000)
if all_recent:
    df_metrics = pd.DataFrame(all_recent, columns=["ID", "Timestamp", "Model", "Test ID", "Category", "Name", "Prompt", "Response", "Status", "Reason"])
    total_count = len(df_metrics)
    pass_count = (df_metrics["Status"] == "PASS").sum()
    fail_count = (df_metrics["Status"] == "FAIL").sum()
    blocked_count = (df_metrics["Status"] == "BLOCKED").sum()
    error_count = (df_metrics["Status"] == "ERROR").sum()
    valid_count = total_count - error_count
    defense_rate = ((pass_count + blocked_count) / valid_count * 100) if valid_count > 0 else 100.0

    c_m1, c_m2, c_m3, c_m4, c_m5 = st.columns(5)
    with c_m1:
        st.markdown(f'<div class="summary-card"><div class="card-title">TỔNG SỰ KIỆN GHI NHẬN</div><div class="card-num" style="color: #e2e8f0;">{total_count}</div><div style="font-size: 0.75rem; color: #94a3b8;">Lỗi hệ thống: {error_count}</div></div>', unsafe_allow_html=True)
    with c_m2:
        st.markdown(f'<div class="summary-card"><div class="card-title" style="color: #fbbf24;">TƯỜNG LỬA CHẶN (BLOCKED)</div><div class="card-num" style="color: #fbbf24;">{blocked_count}</div></div>', unsafe_allow_html=True)
    with c_m3:
        st.markdown(f'<div class="summary-card"><div class="card-title" style="color: #f87171;">BỊ KHAI THÁC (FAIL)</div><div class="card-num" style="color: #f87171;">{fail_count}</div></div>', unsafe_allow_html=True)
    with c_m4:
        st.markdown(f'<div class="summary-card"><div class="card-title" style="color: #4ade80;">AN TOÀN (PASS)</div><div class="card-num" style="color: #4ade80;">{pass_count}</div></div>', unsafe_allow_html=True)
    with c_m5:
        st.markdown(f'<div class="summary-card"><div class="card-title" style="color: #38bdf8;">TỶ LỆ PHÒNG THỦ</div><div class="card-num" style="color: #38bdf8;">{defense_rate:.1f}%</div></div>', unsafe_allow_html=True)

st.write("")

# 3. BIỂU ĐỒ TRỰC QUAN HÓA (RADAR VÀ PIE CHART)
if all_recent:
    st.markdown("### 📈 Ma Trận Phân Tích Rủi Ro An Ninh Thông Tin")
    col_chart_left, col_chart_right = st.columns(2)

    with col_chart_left:
        st.markdown("##### 🎯 Phân bổ Trạng thái Thẩm định Sự cố")
        status_dist = df_metrics["Status"].value_counts().reset_index()
        status_dist.columns = ["Trạng thái", "Số lượng"]
        fig_pie = px.pie(
            status_dist, names="Trạng thái", values="Số lượng",
            color="Trạng thái",
            color_discrete_map={"BLOCKED": "#fbbf24", "FAIL": "#ef4444", "PASS": "#10b981", "ERROR": "#94a3b8"},
            hole=0.4
        )
        fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', font=dict(color="#e2e8f0"), height=320, margin=dict(l=20, r=20, t=20, b=20))
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_chart_right:
        st.markdown("##### 🛡️ Vùng Đề kháng An ninh theo 10 Nhóm OWASP 2026")
        normalized_pairs = [normalize_to_owasp_2026(str(t_id), str(cat)) for t_id, cat in zip(df_metrics["Test ID"], df_metrics["Category"])]
        df_metrics["Mã ID"] = [p[0] for p in normalized_pairs]
        
        owasp_only = df_metrics[df_metrics["Mã ID"].str.startswith("A", na=False) & (df_metrics["Status"] != "ERROR")]
        if not owasp_only.empty:
            cat_stats = owasp_only.groupby("Mã ID").apply(
                lambda x: ((x["Status"].isin(["PASS", "BLOCKED"])).sum() / len(x) * 100) if len(x) > 0 else 0
            ).reset_index()
            cat_stats.columns = ["Mã ID", "Defense_Rate"]
            cats = cat_stats["Mã ID"].tolist()
            rates = cat_stats["Defense_Rate"].tolist()

            fig_radar = go.Figure(go.Scatterpolar(
                r=rates + [rates[0]], theta=cats + [cats[0]],
                fill='toself', name='Tỷ lệ Đề kháng %',
                line_color='#10b981', fillcolor='rgba(16, 185, 129, 0.25)'
            ))
            fig_radar.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, range=[0, 100], gridcolor="rgba(255,255,255,0.15)", tickfont=dict(color="#8b949e")),
                    angularaxis=dict(gridcolor="rgba(255,255,255,0.15)", tickfont=dict(color="#e0e6ed"))
                ),
                paper_bgcolor='rgba(0,0,0,0)', font=dict(color="#e2e8f0"), showlegend=False, height=320, margin=dict(l=40, r=40, t=20, b=20)
            )
            st.plotly_chart(fig_radar, use_container_width=True)
        else:
            st.info("Chưa đủ dữ liệu để vẽ biểu đồ Radar.")

st.divider()

# 4. BẢNG DỮ LIỆU NHẬT KÝ PHÂN TRANG
st.markdown(f"#### 📋 Bảng Nhật ký Kiểm toán Chi tiết (Trang {st.session_state.current_page}/{total_pages} - Tổng {total_records} bản ghi)")

if not paginated_logs:
    st.info("Chưa có bản ghi nhật ký nào phù hợp với bộ lọc.")
else:
    df_p = pd.DataFrame(paginated_logs)
    if "timestamp" in df_p.columns:
        df_p["Thời gian"] = pd.to_datetime(df_p["timestamp"], errors="coerce").dt.strftime("%d/%m/%Y %H:%M:%S").fillna(df_p["timestamp"].astype(str))

    st.dataframe(
        df_p[["Thời gian", "model", "test_id", "category", "status", "prompt", "response", "reason"]],
        column_config={
            "Thời gian": st.column_config.TextColumn("Thời gian", width="medium"),
            "model": st.column_config.TextColumn("Mô hình", width="small"),
            "test_id": st.column_config.TextColumn("Mã ID", width="small"),
            "category": st.column_config.TextColumn("Danh mục OWASP", width="medium"),
            "status": st.column_config.SelectboxColumn("Trạng thái", options=["BLOCKED", "FAIL", "PASS", "ERROR"], width="small"),
            "prompt": st.column_config.TextColumn("Prompt người dùng", width="medium"),
            "response": st.column_config.TextColumn("Phản hồi AI/Proxy", width="medium"),
            "reason": st.column_config.TextColumn("Đánh giá an ninh", width="large")
        },
        use_container_width=True,
        hide_index=True
    )

    # 5. THANH ĐIỀU HƯỚNG PHÂN TRANG (PAGINATION BAR)
    col_p1, col_p2, col_p3 = st.columns([1, 2, 1])
    with col_p1:
        if st.button("⬅️ Trang trước", disabled=(st.session_state.current_page <= 1), use_container_width=True):
            st.session_state.current_page -= 1
            st.rerun()
    with col_p2:
        st.markdown(f"<div style='text-align: center; font-weight: 600; padding-top: 5px;'>Trang {st.session_state.current_page} / {total_pages}</div>", unsafe_allow_html=True)
    with col_p3:
        if st.button("Trang tiếp theo ➡️", disabled=(st.session_state.current_page >= total_pages), use_container_width=True):
            st.session_state.current_page += 1
            st.rerun()

    # Xuất file CSV
    csv_bytes = df_p.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 XUẤT TRANG HIỆN TẠI RA CSV",
        data=csv_bytes,
        file_name=f"SOC_Audit_Page_{st.session_state.current_page}.csv",
        mime="text/csv"
    )