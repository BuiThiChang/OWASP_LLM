import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime

from test_cases import OWASP_TESTS
from ollama_client import get_installed_models
from db_manager import init_db, load_results

# Cấu hình trang Streamlit (Phải đặt ở đầu)
st.set_page_config(page_title="AI Security Dashboard", page_icon="🛡️", layout="wide")

# 1. Nút gạt chuyển đổi giao diện trên Sidebar (Mặc định bật Cyber Neon)
cyber_mode = st.sidebar.toggle("🌌 Chế độ Cyber Neon", value=True)

# 2. Xử lý giao diện động theo trạng thái Toggle (Triệt tiêu hoàn toàn xung đột CSS)
if cyber_mode:
    st.markdown("""
    <style>
        #MainMenu { visibility: hidden !important; }
        .stAppDeployButton { display: none !important; }

        .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"], [data-testid="stMain"] {
            background: radial-gradient(circle at 50% 20%, #0a2353 0%, #041026 60%, #020712 100%) !important;
            background-attachment: fixed !important;
            color: #e6edf3 !important;
        }

        section[data-testid="stSidebar"] {
            background-color: rgba(4, 16, 38, 0.85) !important;
            backdrop-filter: blur(12px);
            border-right: 1px solid rgba(0, 210, 255, 0.3) !important;
        }

        h1, h2, h3 { 
            color: #ffffff !important; 
            text-shadow: 0 0 12px rgba(0, 210, 255, 0.6) !important; 
        }

        div[data-testid="stMetric"] {
            background: rgba(7, 22, 48, 0.75) !important;
            border: 1px solid rgba(0, 210, 255, 0.4) !important;
            border-radius: 12px !important;
        }
        [data-testid="stMetricValue"] {
            color: #00d2ff !important;
            text-shadow: 0 0 14px rgba(0, 210, 255, 0.8) !important;
        }
    </style>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <style>
        #MainMenu { visibility: hidden !important; }
        .stAppDeployButton { display: none !important; }

        .stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"], [data-testid="stMain"] {
            background: #ffffff !important;
            color: #31333F !important;
        }

        section[data-testid="stSidebar"] {
            background-color: #f0f2f6 !important;
            border-right: 1px solid #e0e0e0 !important;
            backdrop-filter: none !important;
        }

        h1, h2, h3, p, span, label { 
            color: #31333F !important; 
            text-shadow: none !important; 
        }

        div[data-testid="stMetric"] {
            background: #f8f9fb !important;
            border: 1px solid #e0e0e0 !important;
            border-radius: 12px !important;
            box-shadow: none !important;
        }
        [data-testid="stMetricValue"] {
            color: #0083B0 !important;
            text-shadow: none !important;
        }
    </style>
    """, unsafe_allow_html=True)

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

# LỌC DỮ LIỆU
results = [
    r for r in all_results 
    if str(r.get("id", "")).startswith("OLLAMA") or str(r.get("test_id", "")).startswith("OLLAMA") or r.get("category") == "Ollama Live Chat"
]

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
tab1, tab_filter, tab2 = st.tabs([
    "📊 Analytics & Audit Log (Ollama App)", 
    "📅 Thống kê nâng cao (Theo Thời gian & Model)", 
    "📚 OWASP LLM Top 10 Reference"
])

with tab1:
    st.header("📊 Nhật ký & Thống kê Tương tác Real-time")
    
    if not results:
        st.info("💡 Chưa có dữ liệu tương tác từ ứng dụng Ollama Desktop. Hãy nhập câu hỏi/prompt bên ứng dụng Ollama để xem nhật ký tại đây!")
    else:
        df = pd.DataFrame(results)

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
                fill='toself', name='Security Score %', line_color='#00d2ff',
                fillcolor='rgba(0, 210, 255, 0.25)'
            ))
            fig.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, range=[0, 100]),
                    angularaxis=dict(gridcolor="rgba(0, 210, 255, 0.2)")
                ), 
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                showlegend=False, 
                height=380
            )
            st.plotly_chart(fig, use_container_width=True)

        with col_chart2:
            st.subheader("📈 Phân bố Trạng thái Phản hồi")
            status_counts = df["status"].value_counts().reset_index()
            status_counts.columns = ["Trạng thái", "Số lượng"]
            st.bar_chart(status_counts.set_index("Trạng thái"), height=380)

        st.divider()

        st.subheader("📋 Bảng Nhật ký Chi tiết (SQLite Database)")
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

        csv = df.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Export Full Audit Log (CSV)", csv, "ollama_security_audit.csv", "text/csv")

# TAB THỐNG KÊ KẾT HỢP BỘ LỌC KHOẢNG THỜI GIAN, LLM VÀ OWASP RIÊNG BỆT
with tab_filter:
    st.header("📅 Thống kê Theo Lọc Khoảng Thời Gian & LLM")
    
    if not all_results:
        st.info("💡 Chưa có dữ liệu kiểm thử trong CSDL.")
    else:
        df_all = pd.DataFrame(all_results)
        df_all["timestamp_dt"] = pd.to_datetime(df_all["timestamp"], errors='coerce')
        
        today = datetime.now()
        first_day_curr_month = today.replace(day=1).date()
        last_day_curr_month = today.date()

        col_f1, col_f2, col_f3 = st.columns(3)
        
        with col_f1:
            date_range = st.date_input(
                "📅 Chọn khoảng thời gian:",
                value=(first_day_curr_month, last_day_curr_month)
            )
            
        with col_f2:
            all_models = ["Tất cả"] + list(df_all["model"].unique())
            selected_model = st.selectbox("🤖 Chọn loại LLM:", all_models)
            
        with col_f3:
            owasp_keys = list(OWASP_TESTS.keys())
            db_cats = df_all["category"].dropna().unique().tolist()
            combined_cats = sorted(list(set(owasp_keys + db_cats)))
            all_cats_options = ["Tất cả"] + combined_cats
            selected_cat = st.selectbox("📌 Chọn nhóm OWASP/Category:", all_cats_options)

        if isinstance(date_range, tuple) and len(date_range) == 2:
            start_date, end_date = date_range
            df_filtered = df_all[
                (df_all["timestamp_dt"].dt.date >= start_date) & 
                (df_all["timestamp_dt"].dt.date <= end_date)
            ]
        else:
            df_filtered = df_all.copy()

        if selected_model != "Tất cả":
            df_filtered = df_filtered[df_filtered["model"] == selected_model]
            
        if selected_cat != "Tất cả":
            df_filtered = df_filtered[df_filtered["category"] == selected_cat]

        st.divider()

        if df_filtered.empty:
            st.warning("⚠️ Không tìm thấy dữ liệu nào phù hợp với bộ lọc đã chọn!")
        else:
            f_total = len(df_filtered)
            f_passed = sum(1 for s in df_filtered["status"] if s == "PASS")
            f_failed = sum(1 for s in df_filtered["status"] if s in ["FAIL", "PROXY-BLOCKED"])
            f_score = (f_passed / f_total * 100) if f_total > 0 else 100

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Tổng lượt trong kỳ", f_total)
            m2.metric("Số lượt An toàn", f_passed)
            m3.metric("Số lượt Vi phạm", f_failed)
            m4.metric("Tỷ lệ An toàn", f"{f_score:.1f}%")

            st.write("---")

            c1, c2 = st.columns(2)
            
            with c1:
                st.subheader("🤖 Số lượt tương tác / kiểm thử theo từng LLM")
                model_counts = df_filtered["model"].value_counts().reset_index()
                model_counts.columns = ["LLM Model", "Số lượt"]
                st.bar_chart(model_counts.set_index("LLM Model"))

            with c2:
                st.subheader("🛡️ Tỷ lệ An toàn (%) theo từng LLM")
                llm_safety = df_filtered.groupby("model")["status"].apply(
                    lambda x: (x == "PASS").sum() / len(x) * 100
                ).reset_index()
                llm_safety.columns = ["LLM Model", "Tỷ lệ An toàn (%)"]
                st.dataframe(llm_safety, use_container_width=True)

            st.subheader("📋 Chi tiết nhật ký đã lọc")
            show_cols_f = ["timestamp", "model", "category", "prompt", "response", "status", "reason"]
            avail_cols_f = [c for c in show_cols_f if c in df_filtered.columns]
            st.dataframe(df_filtered[avail_cols_f], use_container_width=True)

with tab2:
    st.header("📚 Danh mục 10 Nhóm Lỗ hổng OWASP LLM Top 10")
    for cat_name, tests in OWASP_TESTS.items():
        with st.expander(f"📌 {cat_name}"):
            for t in tests:
                st.markdown(f"* **{t['name']}** (`{t['id']}`): {t['prompt']}")