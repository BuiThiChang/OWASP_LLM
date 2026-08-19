import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from test_cases import OWASP_TESTS
from ollama_client import get_installed_models
from db_manager import init_db, load_results

# Cấu hình trang Streamlit
st.set_page_config(page_title="AI Security Dashboard", page_icon="🛡️", layout="wide")

# Khởi tạo CSDL SQLite nếu chưa có
init_db()

# Cấu hình thanh Sidebar
with st.sidebar:
    st.title("🛡️ AI Firewall Monitor")
    st.subheader("Cấu hình mô hình")
    available_models = get_installed_models()
    model = st.selectbox("LLM Model đang giám sát", available_models)

    st.divider()
    st.subheader("📚 Danh mục OWASP LLM")
    for cat in OWASP_TESTS.keys():
        st.caption(f"• {cat}")

# Tiêu đề giao diện
st.title("🛡️ AI Security Dashboard & Real-time Audit Log")
st.caption("Hệ thống giám sát và báo cáo an toàn mô hình ngôn ngữ lớn từ ứng dụng Ollama")

# Tải dữ liệu từ SQLite
all_results = load_results()

# LỌC DỮ LIỆU: Chỉ lấy các nhật ký tương tác thực tế từ App Ollama Desktop (Proxy)
# (Loại bỏ các bản ghi test tự động cũ từ Web nếu có)
results = [
    r for r in all_results 
    if str(r.get("id", "")).startswith("OLLAMA") or str(r.get("test_id", "")).startswith("OLLAMA") or r.get("category") == "Ollama Live Chat"
]

# Nếu chưa có bản ghi lọc, hiển thị toàn bộ nhật ký CSDL để tránh bảng trống
if not results and all_results:
    results = all_results

# BẢNG THỐNG KÊ NHANH (METRICS)
total = len(results)
passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] in ["FAIL", "PROXY-BLOCKED"])
score = (passed / total * 100) if total > 0 else 100

col1, col2, col3, col4 = st.columns(4)
col1.metric("Mô hình đang dùng", model)
col2.metric("Tổng lượt tương tác", total)
col3.metric("Số lượt An toàn (PASS)", passed)
col4.metric("Tỷ lệ An toàn", f"{score:.0f}%")

st.divider()

# TABS HIỂN THỊ THỐNG KÊ
tab1, tab2 = st.tabs(["📊 Analytics & Audit Log (Ollama App)", "📚 OWASP LLM Top 10 Reference"])

with tab1:
    st.header("📊 Nhật ký & Thống kê Tương tác Real-time")
    
    if not results:
        st.info("💡 Chưa có dữ liệu tương tác từ ứng dụng Ollama Desktop. Hãy nhập câu hỏi/prompt bên ứng dụng Ollama để xem nhật ký tại đây!")
    else:
        df = pd.DataFrame(results)

        # Biểu đồ mạng nhện / Biểu đồ tỷ lệ an toàn
        col_chart1, col_chart2 = st.columns([1, 1])
        
        with col_chart1:
            st.subheader("🎯 Tỷ lệ An toàn theo Nhóm")
            cat_stats = df.groupby("category")["status"].apply(lambda x: (x == "PASS").sum() / len(x) * 100).reset_index()
            cat_stats.columns = ["Category", "Score"]

            cats = cat_stats["Category"].tolist()
            scores = cat_stats["Score"].tolist()

            fig = go.Figure(go.Scatterpolar(
                r=scores + [scores[0]] if scores else [],
                theta=cats + [cats[0]] if cats else [],
                fill='toself', name='Security Score %', line_color='#1f77b4'
            ))
            fig.update_layout(polar=dict(radialaxis=dict(visible=True, range=[0, 100])), showlegend=False, height=380)
            st.plotly_chart(fig, use_container_width=True)

        with col_chart2:
            st.subheader("📈 Phân bố Trạng thái Phản hồi")
            status_counts = df["status"].value_counts().reset_index()
            status_counts.columns = ["Trạng thái", "Số lượng"]
            st.bar_chart(status_counts.set_index("Trạng thái"), height=380)

        st.divider()

        # Bảng Audit Log
        st.subheader("📋 Bảng Nhật ký Chi tiết (SQLite Database)")
        
        # Chọn các cột hiển thị quan trọng
        show_cols = ["timestamp", "model", "prompt", "response", "status", "reason"]
        available_cols = [c for c in show_cols if c in df.columns]
        
        st.dataframe(
            df[available_cols], 
            use_container_width=True,
            column_config={
                "timestamp": "Thời gian",
                "model": "Mô hình",
                "prompt": "Prompt Người dùng",
                "response": "Phản hồi AI / Proxy",
                "status": "Trạng thái",
                "reason": "Đánh giá An toàn"
            }
        )

        # Nút Download Báo cáo CSV
        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Export Full Audit Log (CSV)", csv, "ollama_security_audit.csv", "text/csv")

with tab2:
    st.header("📚 Danh mục 10 Nhóm Lỗ hổng OWASP LLM Top 10")
    for cat_name, tests in OWASP_TESTS.items():
        with st.expander(f"📌 {cat_name}"):
            for t in tests:
                st.markdown(f"* **{t['name']}** (`{t['id']}`): {t['prompt']}")