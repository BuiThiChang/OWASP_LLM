import streamlit as st
import pandas as pd
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from db_manager import get_db_connection

st.set_page_config(page_title="Kho Tri thức Nguy cơ An ninh mạng", page_icon="🛡️", layout="wide")

st.title("🛡️ Kho Tri thức Nguy cơ An ninh mạng (Threat Intelligence DB)")
st.caption("Tổng hợp mẫu tấn công từ Red Team & Blue Team phục vụ công tác phân tích nghiệp vụ (A05/PA05)")

try:
    conn = get_db_connection()
    df = pd.read_sql("SELECT * FROM threat_intelligence ORDER BY last_seen DESC", conn)
    conn.close()
except Exception as e:
    st.error(f"❌ Không thể kết nối CSDL Threat Intelligence: {e}")
    st.stop()

if df.empty:
    st.info("ℹ️ Chưa ghi nhận mẫu tri thức nguy cơ nào trong hệ thống.")
else:
    # 1. Thống kê chỉ số nhanh
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("TỔNG MẪU NGUY CƠ", len(df))
    with m2: st.metric("TỪ RED TEAM", len(df[df['detected_source'] == 'RED_TEAM']))
    with m3: st.metric("TỪ BLUE TEAM", len(df[df['detected_source'] == 'BLUE_TEAM']))
    with m4: st.metric("TỔNG LẦN PHÁT HIỆN", df['occurrence_count'].sum())

    st.divider()

    # 2. Bộ lọc nghiệp vụ
    col1, col2 = st.columns(2)
    with col1:
        sources = st.multiselect("Nguồn phát hiện:", options=df['detected_source'].unique(), default=df['detected_source'].unique())
    with col2:
        categories = st.multiselect("Danh mục OWASP:", options=df['owasp_category'].unique(), default=df['owasp_category'].unique())

    filtered_df = df[
        (df['detected_source'].isin(sources)) & 
        (df['owasp_category'].isin(categories))
    ]

    # 3. Bảng hiển thị
    st.markdown(f"### 📋 Danh sách Mẫu Tấn công & Thủ đoạn ({len(filtered_df)})")
    st.dataframe(
        filtered_df[['threat_id', 'vector_type', 'owasp_category', 'attack_payload', 'severity_level', 'detected_source', 'occurrence_count', 'last_seen']],
        column_config={
            "threat_id": "ID",
            "vector_type": "Dạng Tấn công",
            "owasp_category": "Nhóm OWASP",
            "attack_payload": "Nội dung Payload",
            "severity_level": "Mức độ",
            "detected_source": "Nguồn",
            "occurrence_count": "Số lần lặp",
            "last_seen": "Xuất hiện gần nhất"
        },
        use_container_width=True,
        hide_index=True
    )

    # 4. Báo cáo Tham mưu Chiến lược
    st.write("")
    csv_data = filtered_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📄 XUẤT BÁO CÁO THAM MƯU DỰ BÁO NGUY CƠ (.CSV)",
        data=csv_data,
        file_name="A05_PA05_Threat_Intelligence_Report.csv",
        mime="text/csv",
        type="primary"
    )