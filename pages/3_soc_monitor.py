import streamlit as st
import pandas as pd
import plotly.express as px
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from db_manager import get_recent_logs

st.set_page_config(
    page_title="SOC Security Monitor & Audit Trail - LLMVault",
    page_icon="📊",
    layout="wide"
)

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
        background-color: rgba(16, 185, 129, 0.05);
        border: 1px solid rgba(16, 185, 129, 0.2);
        border-radius: 8px;
        padding: 12px 16px;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="green-header">
    <div class="green-title">📊 MODULE 03: SOC SECURITY MONITOR & OWASP TOP 10 AUDIT TRAIL</div>
    <div style="opacity: 0.8; font-size: 0.95rem;">Trung tâm giám sát nhật ký an ninh, truy vết dữ liệu sự cố từ các phiên chạy Red Team & Sandbox thực tế.</div>
</div>
""", unsafe_allow_html=True)

raw_logs = get_recent_logs(500)

if not raw_logs:
    st.info("ℹ️ Chưa có dữ liệu nhật ký sự cố. Hãy thực hiện kiểm thử ở Module Red Team hoặc Live Sandbox để ghi nhận lịch sử vào SOC.")
else:
    df = pd.DataFrame(raw_logs, columns=[
        "ID", "Timestamp", "Model", "Test ID", "Category", 
        "Name", "Prompt", "Response", "Status", "Reason"
    ])
    
    c_m1, c_m2, c_m3, c_m4 = st.columns(4)
    
    total_count = len(df)
    safe_count = len(df[df["Status"].isin(["SAFE", "PASS"])])
    blocked_count = len(df[df["Status"].isin(["BLOCKED", "FAIL"])])
    error_count = len(df[df["Status"] == "ERROR"])
    
    with c_m1:
        st.markdown(f'<div class="summary-card"><div style="font-size:0.8rem; opacity:0.8;">TỔNG LOGS GHI NHẬN</div><div style="font-size:1.6rem; font-weight:bold;">{total_count}</div></div>', unsafe_allow_html=True)
    with c_m2:
        st.markdown(f'<div class="summary-card"><div style="font-size:0.8rem; color:#4ade80;">AN TOÀN (SAFE)</div><div style="font-size:1.6rem; font-weight:bold; color:#4ade80;">{safe_count}</div></div>', unsafe_allow_html=True)
    with c_m3:
        st.markdown(f'<div class="summary-card"><div style="font-size:0.8rem; color:#f87171;">ĐÃ CHẶN (BLOCKED)</div><div style="font-size:1.6rem; font-weight:bold; color:#f87171;">{blocked_count}</div></div>', unsafe_allow_html=True)
    with c_m4:
        st.markdown(f'<div class="summary-card"><div style="font-size:0.8rem; color:#fbbf24;">LỖI HỆ THỐNG (ERROR)</div><div style="font-size:1.6rem; font-weight:bold; color:#fbbf24;">{error_count}</div></div>', unsafe_allow_html=True)

    st.write("")
    
    f_col1, f_col2, f_col3 = st.columns([1, 1, 2])
    
    with f_col1:
        status_filter = st.multiselect(
            "Lọc theo Status:",
            options=["SAFE", "BLOCKED", "ERROR", "PASS", "FAIL"],
            default=["SAFE", "BLOCKED", "ERROR"]
        )
        
    with f_col2:
        all_owasp_cats = ["Tất cả"] + list(df["Category"].dropna().unique())
        cat_filter = st.selectbox("Lọc theo Danh mục OWASP:", options=all_owasp_cats)
        
    with f_col3:
        search_kw = st.text_input("🔍 Tìm kiếm theo Từ khóa (Prompt/Reason):", value="")

    filtered_df = df[df["Status"].isin(status_filter)]
    
    if cat_filter != "Tất cả":
        filtered_df = filtered_df[filtered_df["Category"] == cat_filter]
        
    if search_kw.strip():
        kw = search_kw.lower()
        filtered_df = filtered_df[
            filtered_df["Prompt"].str.lower().str.contains(kw, na=False) | 
            filtered_df["Reason"].str.lower().str.contains(kw, na=False)
        ]

    st.divider()

    st.markdown("### 📈 Phân Tích Ma Trận Lỗ Hổng OWASP LLM Top 10 (Từ Lịch Sử Thực Tế)")
    
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        status_counts = filtered_df["Status"].value_counts().reset_index()
        status_counts.columns = ["Trạng thái", "Số lượng"]
        
        fig_pie = px.pie(
            status_counts, 
            names="Trạng thái", 
            values="Số lượng", 
            title="Tỉ lệ Phân bổ Trạng thái Kiểm thử Thực tế",
            color="Trạng thái",
            color_discrete_map={"SAFE": "#10b981", "PASS": "#10b981", "BLOCKED": "#ef4444", "FAIL": "#ef4444", "ERROR": "#f59e0b"}
        )
        st.plotly_chart(fig_pie, width="stretch")

    with col_chart2:
        blocked_df = filtered_df[filtered_df["Status"].isin(["BLOCKED", "FAIL"])]
        if not blocked_df.empty:
            cat_counts = blocked_df["Category"].value_counts().reset_index()
            cat_counts.columns = ["Danh mục OWASP", "Số vi phạm (BLOCKED)"]
            
            fig_bar = px.bar(
                cat_counts, 
                x="Danh mục OWASP", 
                y="Số vi phạm (BLOCKED)",
                title="Mật độ Tấn công bị Ngăn chặn (BLOCKED)",
                color_discrete_sequence=["#ef4444"]
            )
            st.plotly_chart(fig_bar, width="stretch")
        else:
            st.success("🎉 Hệ thống an toàn! Chưa ghi nhận vi phạm nào trong bộ lọc hiện tại.")

    st.markdown(f"#### 📋 Bảng Nhật ký Chi tiết Audit Trail ({len(filtered_df)} bản ghi)")
    
    df_display = filtered_df[["Timestamp", "Model", "Test ID", "Category", "Status", "Prompt", "Response", "Reason"]]
    
    # Bảng dữ liệu DataFrame
    st.dataframe(
    df_display,
    column_config={
        "Timestamp": st.column_config.DatetimeColumn("Thời gian", format="DD/MM/YYYY HH:mm:ss"),
        "Category": st.column_config.TextColumn("Nhóm OWASP"),
        "Prompt": st.column_config.TextColumn("Prompt đầu vào", width="medium"),
        "Response": st.column_config.TextColumn("Phản hồi hệ thống", width="large"),
    },
    width="stretch",
    hide_index=True
)

    st.write("")
    csv_data = filtered_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 XUẤT BÁO CÁO SOC AUDIT (.CSV)",
        data=csv_data,
        file_name="LLMVault_SOC_OWASP_Audit_Report.csv",
        mime="text/csv",
        type="primary"
    )