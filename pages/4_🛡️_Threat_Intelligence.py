"""
FILE: pages/4_threat_intelligence.py
Mô tả: Phân hệ Kho Tri thức Nguy cơ An ninh mạng (Threat Intelligence DB).
- Tổng hợp mẫu payload tấn công từ Red Team & Blue Team (Tường lửa Proxy)
- Chuẩn hóa phân loại theo 10 nhóm OWASP 2026 (A01 -> A10)
- Quản lý đóng/trả kết nối PostgreSQL Pool an toàn chống rò rỉ kết nối
- Định dạng chuẩn cột thời gian xuất hiện: DD/MM/YYYY HH:MM:SS
"""

import streamlit as st
import pandas as pd
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from db_manager import get_db_connection, release_db_connection
from security_engine import normalize_to_owasp_2026

st.set_page_config(page_title="Kho Tri thức Nguy cơ An ninh mạng", page_icon="🛡️", layout="wide")

st.title("🛡️ Kho Tri thức Nguy cơ An ninh mạng (Threat Intelligence DB)")
st.caption("Tổng hợp mẫu tấn công từ Red Team & Blue Team phục vụ công tác phân tích nghiệp vụ (Chuẩn OWASP 2026)")

conn = None
try:
    conn = get_db_connection()
    df = pd.read_sql("SELECT * FROM threat_intelligence ORDER BY last_seen DESC", conn)
except Exception as e:
    st.error(f"❌ Không thể kết nối CSDL Threat Intelligence: {e}")
    st.stop()
finally:
    if conn:
        release_db_connection(conn)

if df.empty:
    st.info("ℹ️ Chưa ghi nhận mẫu tri thức nguy cơ nào trong hệ thống.")
else:
    # 1. CHUẨN HÓA CỘT THỜI GIAN LAST_SEEN
    def parse_threat_time(val):
        if pd.isna(val) or val == "" or val is None:
            return ""
        try:
            num = float(val)
            if num > 1e11:
                return pd.to_datetime(num, unit="ms").strftime("%d/%m/%Y %H:%M:%S")
            elif num > 1e8:
                return pd.to_datetime(num, unit="s").strftime("%d/%m/%Y %H:%M:%S")
        except (ValueError, TypeError):
            pass
        try:
            dt = pd.to_datetime(val, errors="coerce")
            if pd.notna(dt):
                return dt.strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            pass
        return str(val)

    if 'last_seen' in df.columns:
        df["Xuất hiện gần nhất"] = df["last_seen"].apply(parse_threat_time)
        
    # 2. Chuẩn hóa danh mục nguy cơ về hệ 10 nhóm OWASP 2026
    normalized_list = [normalize_to_owasp_2026("", str(cat)) for cat in df['owasp_category']]
    df['Mã nhóm'] = [p[0] for p in normalized_list]
    df['Nhóm OWASP Chuẩn'] = [p[1] for p in normalized_list]

    # 3. Thống kê chỉ số nhanh
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("TỔNG MẪU NGUY CƠ", len(df))
    with m2: st.metric("TỪ RED TEAM", len(df[df['detected_source'] == 'RED_TEAM']))
    with m3: st.metric("TỪ BLUE TEAM", len(df[df['detected_source'] == 'BLUE_TEAM']))
    with m4: st.metric("TỔNG LẦN PHÁT HIỆN", int(df['occurrence_count'].sum()) if 'occurrence_count' in df else len(df))

    st.divider()

    # 4. Bộ lọc nghiệp vụ
    col1, col2 = st.columns(2)
    with col1:
        sources = st.multiselect("Nguồn phát hiện:", options=df['detected_source'].unique(), default=df['detected_source'].unique())
    with col2:
        categories = st.multiselect("Danh mục OWASP 2026:", options=sorted(df['Nhóm OWASP Chuẩn'].unique()), default=sorted(df['Nhóm OWASP Chuẩn'].unique()))

    filtered_df = df[
        (df['detected_source'].isin(sources)) & 
        (df['Nhóm OWASP Chuẩn'].isin(categories))
    ]

    # 5. Bảng hiển thị
    st.markdown(f"### 📋 Danh sách Mẫu Tấn công & Thủ đoạn ({len(filtered_df)})")
    show_cols = ['id', 'signature_hash', 'vector_type', 'Nhóm OWASP Chuẩn', 'attack_payload',
                 'detected_source', 'detector_rule', 'occurrence_count', 'Xuất hiện gần nhất']
    st.dataframe(
        filtered_df[[c for c in show_cols if c in filtered_df.columns]],
        column_config={
            "id": st.column_config.NumberColumn("ID", width="small"),
            "signature_hash": st.column_config.TextColumn("Chữ ký SHA-256", width="small"),
            "vector_type": st.column_config.TextColumn("Dạng Tấn công", width="medium"),
            "Nhóm OWASP Chuẩn": st.column_config.TextColumn("Nhóm OWASP 2026", width="large"),
            "attack_payload": st.column_config.TextColumn("Nội dung Payload", width="large"),
            "detected_source": st.column_config.TextColumn("Nguồn", width="small"),
            "detector_rule": st.column_config.TextColumn("Luật phát hiện", width="medium"),
            "occurrence_count": st.column_config.NumberColumn("Số lần lặp", width="small"),
            "Xuất hiện gần nhất": st.column_config.TextColumn("Xuất hiện gần nhất", width="medium")
        },
        use_container_width=True,
        hide_index=True
    )

    # 6. Báo cáo Tham mưu Chiến lược
    st.write("")
    csv_data = filtered_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📄 XUẤT BÁO CÁO THAM MƯU DỰ BÁO NGUY CƠ (.CSV)",
        data=csv_data,
        file_name="A05_PA05_Threat_Intelligence_Report_2026.csv",
        mime="text/csv",
        type="primary"
    )