"""
FILE: pages/3_soc_monitor.py
Mô tả: Module 03 - Trung tâm Giám sát An ninh (SOC Monitor & Audit Trail).
- Chuẩn hóa cột thời gian từ Epoch Unix sang DD/MM/YYYY HH:MM:SS
- Đồng bộ CSDL chuẩn 3 trạng thái: BLOCKED | FAIL | PASS
- Tự động chuẩn hóa toàn bộ mã ID và danh mục theo OWASP 2026 (A01 -> A10)
- Trực quan hóa ma trận rủi ro qua Biểu đồ Radar và Pie Chart
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sys
import os

# 1. THIẾT LẬP ĐƯỜNG DẪN IMPORT TỪ THƯ MỤC GỐC
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from db_manager import get_recent_logs
from security_engine import normalize_to_owasp_2026

# 2. CẤU HÌNH TRANG STREAMLIT
st.set_page_config(
    page_title="SOC Security Monitor & Audit Trail - CAND",
    page_icon="📊",
    layout="wide"
)

# 3. CSS TÙY CHỈNH THEO PHONG CÁCH SOC CYBER DEFENSE (TONE EMERALD/GREEN)
st.markdown("""
<style>
    .stAppDeployButton, button[title="Deploy this app"], [data-testid="stAppDeployButton"], footer {
        display: none !important;
    }
    .green-header {
        border-left: 5px solid #10b981;
        padding-left: 15px;
        margin-bottom: 20px;
    }
    .green-title {
        color: #34d399;
        font-weight: 700;
        font-size: 1.8rem;
    }
    .summary-card {
        background-color: rgba(16, 185, 129, 0.04);
        border: 1px solid rgba(16, 185, 129, 0.25);
        border-radius: 8px;
        padding: 14px 18px;
        text-align: center;
        box-shadow: 0 4px 12px rgba(0,0,0,0.25);
    }
    .card-title {
        font-size: 0.8rem;
        opacity: 0.8;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .card-num {
        font-size: 1.8rem;
        font-weight: 700;
        margin-top: 4px;
        font-family: monospace;
    }
</style>
""", unsafe_allow_html=True)

# 4. TIÊU ĐỀ MODULE
st.markdown("""
<div class="green-header">
    <div class="green-title">📊 MODULE 03: SOC SECURITY OPERATIONS CENTER & AUDIT TRAIL</div>
    <div style="opacity: 0.85; font-size: 0.95rem;">
        Trung tâm tiếp nhận sự kiện, phân tích nhật ký an ninh và giám sát khả năng phòng thủ của hệ thống AI theo thời gian thực (Chuẩn OWASP 2026).
    </div>
</div>
""", unsafe_allow_html=True)

# 5. TẢI DỮ LIỆU NHẬT KÝ TỪ CƠ SỞ DỮ LIỆU
raw_logs = get_recent_logs(1000)

if not raw_logs:
    st.info("ℹ️ Hiện chưa có dữ liệu nhật ký sự cố trong CSDL. Hãy thực hiện kiểm thử tự động ở **Module 01 (Red Team)** hoặc tương tác trực tiếp ở **Module 02 (Live Sandbox)** để hệ thống ghi nhận sự kiện.")
else:
    df = pd.DataFrame(raw_logs, columns=[
        "ID", "Timestamp", "Model", "Test ID", "Category", 
        "Name", "Prompt", "Response", "Status", "Reason"
    ])

    # 5.1. XỬ LÝ CHUẨN HÓA CỘT THỜI GIAN (KHẮC PHỤC TRIỆT ĐỂ ASSERTIONERROR)
    def parse_smart_datetime(val):
        if pd.isna(val) or val == "" or val is None:
            return ""
        # Thử ép sang số (epoch timestamp)
        try:
            num = float(val)
            if num > 1e11:  # mili-giây
                return pd.to_datetime(num, unit="ms").strftime("%d/%m/%Y %H:%M:%S")
            elif num > 1e8:  # giây
                return pd.to_datetime(num, unit="s").strftime("%d/%m/%Y %H:%M:%S")
        except (ValueError, TypeError):
            pass
        
        # Thử ép chuỗi datetime chuẩn (ISO hoặc chuỗi thông thường)
        try:
            dt = pd.to_datetime(val, errors="coerce")
            if pd.notna(dt):
                return dt.strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            pass
        return str(val)

    df["Thời gian"] = df["Timestamp"].apply(parse_smart_datetime)
    
    # 5.2. CHUẨN HÓA TOÀN BỘ MÃ ID VÀ DANH MỤC THEO BỘ QUY CHUẨN 2026
    normalized_pairs = [normalize_to_owasp_2026(str(t_id), str(cat)) for t_id, cat in zip(df["Test ID"], df["Category"])]
    df["Mã ID"] = [p[0] for p in normalized_pairs]
    df["Danh mục nguy cơ"] = [p[1] for p in normalized_pairs]

    # Chuẩn hóa trạng thái về 3 trạng thái duy nhất
    def normalize_status(val):
        s = str(val).upper().strip()
        if s in ["BLOCKED", "PROXY-BLOCKED"]:
            return "BLOCKED"
        elif s in ["FAIL", "FAILED", "EXPLOITED", "VULNERABLE"]:
            return "FAIL"
        else:
            return "PASS"

    df["Trạng thái"] = df["Status"].apply(normalize_status)

    # 6. KHUNG CHỈ SỐ THỐNG KÊ TỔNG QUAN (KPI METRIC CARDS)
    total_count = len(df)
    pass_count = (df["Trạng thái"] == "PASS").sum()
    fail_count = (df["Trạng thái"] == "FAIL").sum()
    blocked_count = (df["Trạng thái"] == "BLOCKED").sum()
    defense_rate = ((pass_count + blocked_count) / total_count * 100) if total_count > 0 else 100.0

    c_m1, c_m2, c_m3, c_m4, c_m5 = st.columns(5)
    with c_m1:
        st.markdown(f'''
            <div class="summary-card">
                <div class="card-title">TỔNG SỰ KIỆN GHI NHẬN</div>
                <div class="card-num" style="color: #e2e8f0;">{total_count}</div>
            </div>
        ''', unsafe_allow_html=True)
    with c_m2:
        st.markdown(f'''
            <div class="summary-card">
                <div class="card-title" style="color: #fbbf24;">TƯỜNG LỬA CHẶN (BLOCKED)</div>
                <div class="card-num" style="color: #fbbf24;">{blocked_count}</div>
            </div>
        ''', unsafe_allow_html=True)
    with c_m3:
        st.markdown(f'''
            <div class="summary-card">
                <div class="card-title" style="color: #f87171;">BỊ KHAI THÁC (FAIL)</div>
                <div class="card-num" style="color: #f87171;">{fail_count}</div>
            </div>
        ''', unsafe_allow_html=True)
    with c_m4:
        st.markdown(f'''
            <div class="summary-card">
                <div class="card-title" style="color: #4ade80;">AN TOÀN / TỰ VỆ (PASS)</div>
                <div class="card-num" style="color: #4ade80;">{pass_count}</div>
            </div>
        ''', unsafe_allow_html=True)
    with c_m5:
        st.markdown(f'''
            <div class="summary-card">
                <div class="card-title" style="color: #38bdf8;">TỶ LỆ PHÒNG THỦ</div>
                <div class="card-num" style="color: #38bdf8;">{defense_rate:.1f}%</div>
            </div>
        ''', unsafe_allow_html=True)

    st.write("")

    # 7. KHU VỰC CÔNG CỤ BỘ LỌC ĐA CHIỀU
    st.markdown("#### 🔍 Bộ Lọc & Tra Cứu Sự Cố An Ninh")
    f_col1, f_col2, f_col3, f_col4 = st.columns([1, 1.2, 1, 1.8])

    with f_col1:
        status_options = ["BLOCKED", "FAIL", "PASS"]
        status_filter = st.multiselect("Lọc trạng thái:", options=status_options, default=status_options)

    with f_col2:
        cats_in_db = ["Tất cả"] + sorted(list(df["Danh mục nguy cơ"].dropna().unique()))
        selected_cat = st.selectbox("Lọc theo Danh mục:", options=cats_in_db)

    with f_col3:
        models_in_db = ["Tất cả"] + sorted(list(df["Model"].dropna().unique()))
        selected_model = st.selectbox("Lọc theo Mô hình:", options=models_in_db)

    with f_col4:
        search_kw = st.text_input("Tìm kiếm theo chuỗi Prompt / Lý do thẩm định:", value="")

    # Thực hiện lọc
    filtered_df = df[df["Trạng thái"].isin(status_filter)]
    if selected_cat != "Tất cả":
        filtered_df = filtered_df[filtered_df["Danh mục nguy cơ"] == selected_cat]
    if selected_model != "Tất cả":
        filtered_df = filtered_df[filtered_df["Model"] == selected_model]
    if search_kw.strip():
        kw = search_kw.lower()
        filtered_df = filtered_df[
            filtered_df["Prompt"].str.lower().str.contains(kw, na=False) | 
            filtered_df["Reason"].str.lower().str.contains(kw, na=False)
        ]

    st.divider()

    # 8. BIỂU ĐỒ TRỰC QUAN HÓA (RADAR CHART & PIE CHART)
    st.markdown("### 📈 Ma Trận Phân Tích Rủi Ro An Ninh Thông Tin")
    col_chart_left, col_chart_right = st.columns(2)

    with col_chart_left:
        st.markdown("##### 🎯 Phân bổ Trạng thái Thẩm định Sự cố")
        status_dist = filtered_df["Trạng thái"].value_counts().reset_index()
        status_dist.columns = ["Trạng thái", "Số lượng"]
        
        color_mapping = {
            "BLOCKED": "#fbbf24",
            "FAIL": "#ef4444",
            "PASS": "#10b981"
        }
        
        fig_pie = px.pie(
            status_dist,
            names="Trạng thái",
            values="Số lượng",
            color="Trạng thái",
            color_discrete_map=color_mapping,
            hole=0.4
        )
        fig_pie.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#e2e8f0"),
            height=340,
            margin=dict(l=20, r=20, t=20, b=20)
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with col_chart_right:
        st.markdown("##### 🛡️ Vùng Đề kháng An ninh theo 10 Nhóm OWASP 2026")
        
        # Chỉ tính tỷ lệ trên các nhóm A01 -> A10
        owasp_only = filtered_df[filtered_df["Mã ID"].str.startswith("A", na=False)]
        
        if not owasp_only.empty:
            cat_stats = owasp_only.groupby("Mã ID").apply(
                lambda x: ((x["Trạng thái"].isin(["PASS", "BLOCKED"])).sum() / len(x) * 100) if len(x) > 0 else 0
            ).reset_index()
            cat_stats.columns = ["Mã ID", "Defense_Rate"]

            cats = cat_stats["Mã ID"].tolist()
            rates = cat_stats["Defense_Rate"].tolist()

            fig_radar = go.Figure(go.Scatterpolar(
                r=rates + [rates[0]],
                theta=cats + [cats[0]],
                fill='toself',
                name='Tỷ lệ Đề kháng %',
                line_color='#10b981',
                fillcolor='rgba(16, 185, 129, 0.25)'
            ))
            fig_radar.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, range=[0, 100], gridcolor="rgba(255,255,255,0.15)", tickfont=dict(color="#8b949e")),
                    angularaxis=dict(gridcolor="rgba(255,255,255,0.15)", tickfont=dict(color="#e0e6ed"))
                ),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color="#e2e8f0"),
                showlegend=False,
                height=340,
                margin=dict(l=40, r=40, t=20, b=20)
            )
            st.plotly_chart(fig_radar, use_container_width=True)
        else:
            st.info("Chưa đủ dữ liệu nhóm OWASP để dựng biểu đồ Radar.")

    # 9. BẢNG NHẬT KÝ KIỂM TOÁN CHI TIẾT
    st.markdown(f"#### 📋 Bảng Nhật ký Kiểm toán Chi tiết ({len(filtered_df)} bản ghi)")

    st.dataframe(
        filtered_df[["Thời gian", "Model", "Mã ID", "Danh mục nguy cơ", "Trạng thái", "Prompt", "Response", "Reason"]],
        column_config={
            "Thời gian": st.column_config.TextColumn("Thời gian", width="medium"),
            "Model": st.column_config.TextColumn("Mô hình", width="small"),
            "Mã ID": st.column_config.TextColumn("Mã ID", width="small"),
            "Danh mục nguy cơ": st.column_config.TextColumn("Danh mục nguy cơ", width="large"),
            "Trạng thái": st.column_config.SelectboxColumn(
                "Trạng thái",
                options=["BLOCKED", "FAIL", "PASS"],
                width="small"
            ),
            "Prompt": st.column_config.TextColumn("Prompt người dùng", width="medium"),
            "Response": st.column_config.TextColumn("Phản hồi AI/Proxy", width="medium"),
            "Reason": st.column_config.TextColumn("Đánh giá an toàn", width="large")
        },
        use_container_width=True,
        hide_index=True
    )

    # 10. XUẤT BÁO CÁO CSV
    st.write("")
    csv_bytes = filtered_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 XUẤT BÁO CÁO SOC AUDIT REPORT (.CSV)",
        data=csv_bytes,
        file_name="SOC_AI_Security_Audit_Report.csv",
        mime="text/csv",
        type="primary"
    )