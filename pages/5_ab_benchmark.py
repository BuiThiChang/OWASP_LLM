"""
FILE: pages/4_ab_benchmark.py
Mô tả: Phân hệ Benchmark đối chứng A/B (Baseline vs. AI Guardrail Proxy).
- Nạp kịch bản thực tế từ test_cases.py (Dữ liệu Red Team Audit)
- Tự động thực thi đối chiếu 2 luồng: Trực tiếp (11436) vs. Qua Tường lửa (11435)
- Tính toán chính xác các chỉ số định lượng: Attack Mitigation Rate, Vulnerability Rate
- Vẽ biểu đồ đối sánh trực quan từ dữ liệu thực nghiệm
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import requests
import time
import sys
import os

# 1. CẤU HÌNH ĐƯỜNG DẪN VÀ IMPORT
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

from test_cases import OWASP_TESTS
from security_engine import evaluate_full_cycle

# 2. CẤU HÌNH GIAO DIỆN STREAMLIT
st.set_page_config(
    page_title="A/B Benchmark & Mitigation Analysis",
    page_icon="⚖️",
    layout="wide"
)

st.markdown("""
<style>
    .benchmark-header {
        border-left: 5px solid #00f3ff;
        padding-left: 15px;
        margin-bottom: 20px;
    }
    .benchmark-title {
        color: #00f3ff;
        font-weight: 700;
        font-size: 1.8rem;
    }
    .box-unprotected {
        background-color: rgba(239, 68, 68, 0.08);
        border: 1px solid rgba(239, 68, 68, 0.4);
        border-radius: 8px;
        padding: 14px;
        min-height: 200px;
    }
    .box-protected {
        background-color: rgba(16, 185, 129, 0.08);
        border: 1px solid rgba(16, 185, 129, 0.4);
        border-radius: 8px;
        padding: 14px;
        min-height: 200px;
    }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="benchmark-header">
    <div class="benchmark-title">⚖️ A/B BENCHMARK: ĐÁNH GIÁ ĐỊNH LƯỢNG HIỆU QUẢ TƯỜNG LỬA</div>
    <div style="opacity: 0.85; font-size: 0.95rem;">
        Kiểm thử đối chứng tự động giữa <b>Mô hình Trực tiếp (Baseline - 11436)</b> và <b>Mô hình có Tường lửa (Protected - 11435)</b>.
    </div>
</div>
""", unsafe_allow_html=True)

DIRECT_OLLAMA_URL = "http://localhost:11436/api/chat"
PROXY_FIREWALL_URL = "http://localhost:11435/v1/chat/completions"
SECRET_KEY = "OWASP-LLM-TEST-2026-7F3A9C"

# 3. KHỞI TẠO SESSION STATE LƯU KẾT QUẢ THỰC NGHIỆM
if "benchmark_results" not in st.session_state:
    st.session_state.benchmark_results = None

# 4. KHU VỰC 1: ĐIỀU KHIỂN CHẠY BATCH BENCHMARK TOÀN DIỆN
st.markdown("### 🚀 Thực nghiệm Toàn diện trên Tập Kịch bản Red Team")

c_opt1, c_opt2 = st.columns([2, 1])
with c_opt1:
    target_model = st.text_input("Mô hình mục tiêu:", value="llama3.2:3b")
with c_opt2:
    selected_cats = st.multiselect(
        "Nhóm OWASP đưa vào Benchmark:",
        options=list(OWASP_TESTS.keys()),
        default=list(OWASP_TESTS.keys())
    )

# Thu thập danh sách test case từ file test_cases.py
benchmark_cases = []
for cat in selected_cats:
    for case in OWASP_TESTS.get(cat, []):
        benchmark_cases.append({"category": cat, **case})

st.caption(f"Tổng số kịch bản Red Team sẵn sàng thực nghiệm: **{len(benchmark_cases)}** ca kiểm thử.")

if st.button("🔥 BẮT ĐẦU CHẠY BENCHMARK ĐỐI CHỨNG (RUN A/B AUDIT)", type="primary"):
    if not benchmark_cases:
        st.warning("Vui lòng chọn ít nhất một danh mục!")
    else:
        progress_bar = st.progress(0)
        status_info = st.empty()
        
        records = []
        total_runs = len(benchmark_cases)

        for idx, item in enumerate(benchmark_cases):
            cat = item["category"]
            prompt = item["prompt"]
            cid = item["id"]
            name = item["name"]

            status_info.markdown(f"⏳ Đang chạy kịch bản **[{idx+1}/{total_runs}]**: `{name}`...")

            # --- NHÁNH 1: GỬI TRỰC TIẾP OLLAMA (BASELINE - PORT 11436) ---
            t0 = time.time()
            try:
                r_direct = requests.post(DIRECT_OLLAMA_URL, json={
                    "model": target_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False
                }, timeout=250)
                lat_direct = round(time.time() - t0, 3)
                
                if r_direct.status_code == 200:
                    text_direct = r_direct.json().get("message", {}).get("content", "")
                else:
                    text_direct = f"Lỗi HTTP {r_direct.status_code}"
            except Exception as e:
                lat_direct = 0
                text_direct = f"Lỗi kết nối: {str(e)}"

            # Thẩm định an ninh cho luồng trực tiếp
            verdict_direct, reason_direct = evaluate_full_cycle(
                category_code=cat,
                prompt=prompt,
                response_text=text_direct,
                status_code=200,
                secret=SECRET_KEY
            )

            # --- NHÁNH 2: GỬI QUA TƯỜNG LỬA PROXY (PORT 11435) ---
            t1 = time.time()
            try:
                r_proxy = requests.post(PROXY_FIREWALL_URL, json={
                    "model": target_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False
                }, timeout=250)
                lat_proxy = round(time.time() - t1, 3)
                
                if r_proxy.status_code == 200:
                    text_proxy = r_proxy.json().get("choices", [{}])[0].get("message", {}).get("content", "")
                elif r_proxy.status_code == 403:
                    text_proxy = "[BLOCKED BY SECURITY FIREWALL]"
                else:
                    text_proxy = f"Lỗi HTTP {r_proxy.status_code}"
            except Exception as e:
                lat_proxy = 0
                text_proxy = f"Lỗi kết nối: {str(e)}"

            # Thẩm định an ninh cho luồng qua Proxy
            verdict_proxy, reason_proxy = evaluate_full_cycle(
                category_code=cat,
                prompt=prompt,
                response_text=text_proxy,
                status_code=r_proxy.status_code if 'r_proxy' in locals() else 500,
                secret=SECRET_KEY
            )

            records.append({
                "id": cid,
                "category": cat,
                "name": name,
                "prompt": prompt,
                "status_direct": verdict_direct,      # Trạng thái luồng không tường lửa
                "response_direct": text_direct,
                "latency_direct": lat_direct,
                "status_proxy": verdict_proxy,        # Trạng thái luồng qua tường lửa
                "response_proxy": text_proxy,
                "latency_proxy": lat_proxy
            })

            progress_bar.progress((idx + 1) / total_runs)

        status_info.success("🎉 Đã hoàn tất đối chứng toàn bộ kịch bản Red Team!")
        st.session_state.benchmark_results = pd.DataFrame(records)

st.divider()

# 5. KHU VỰC 2: TÍNH TOÁN CÁC CHỈ SỐ TOÁN HỌC TỰ ĐỘNG
if st.session_state.benchmark_results is not None:
    df = st.session_state.benchmark_results
    total_tests = len(df)

    # 1. Đếm số lượng lỗ hổng thực tế
    fail_direct = (df["status_direct"] == "FAIL").sum()
    fail_proxy = (df["status_proxy"] == "FAIL").sum()
    blocked_proxy = (df["status_proxy"] == "BLOCKED").sum()

    # 2. Tính toán tỷ lệ phần trăm chính xác
    vuln_rate_direct = (fail_direct / total_tests * 100) if total_tests > 0 else 0
    vuln_rate_proxy = (fail_proxy / total_tests * 100) if total_tests > 0 else 0

    # 3. Hiệu suất triệt tiêu tấn công (Mitigation Efficiency)
    # Tỷ lệ các ca bị khai thác ở Baseline nhưng đã được ngăn chặn thành công khi qua Proxy
    mitigated_count = len(df[(df["status_direct"] == "FAIL") & (df["status_proxy"].isin(["BLOCKED", "PASS"]))])
    mitigation_rate = (mitigated_count / fail_direct * 100) if fail_direct > 0 else 100.0

    # 4. Độ trễ trung bình tăng thêm do Proxy
    avg_lat_direct = df["latency_direct"].mean()
    avg_lat_proxy = df["latency_proxy"].mean()
    overhead_ms = max(0.0, (avg_lat_proxy - avg_lat_direct) * 1000)

    # HIỂN THỊ CÁC THẺ METRIC TÍNH TOÁN THỰC
    st.markdown("### 📊 Các Chỉ Số Định Lượng Thực Nghiệm (Live Calculated Metrics)")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("TỔNG KỊCH BẢN THỬ NGHIỆM", f"{total_tests} Cases")
    m2.metric(
        "TỶ LỆ LỖ HỔNG (BASELINE)", 
        f"{vuln_rate_direct:.1f}%", 
        delta=f"{fail_direct}/{total_tests} ca phơi nhiễm", 
        delta_color="inverse"
    )
    m3.metric(
        "TỶ LỆ LỖ HỔNG (CÓ PROXY)", 
        f"{vuln_rate_proxy:.1f}%", 
        delta=f"-{vuln_rate_direct - vuln_rate_proxy:.1f}% Rủi ro", 
        delta_color="normal"
    )
    m4.metric(
        "HIỆU SUẤT TRIỆT TIÊU (MITIGATION)", 
        f"{mitigation_rate:.1f}%", 
        delta=f"Độ trễ trung bình +{overhead_ms:.1f}ms", 
        delta_color="normal"
    )

    st.write("")

    # 6. KHU VỰC 3: BIỂU ĐỒ ĐỐI SÁNH TỰ ĐỘNG TỪ SỐ LIỆU ĐÃ CHẠY
    c_chart1, c_chart2 = st.columns(2)

    with c_chart1:
        # Nhóm theo category để tính tỷ lệ FAIL của từng nhóm
        cat_stats = df.groupby("category").apply(lambda x: pd.Series({
            "fail_direct": (x["status_direct"] == "FAIL").sum() / len(x) * 100,
            "fail_proxy": (x["status_proxy"] == "FAIL").sum() / len(x) * 100
        })).reset_index()

        fig_bar = go.Figure()
        fig_bar.add_trace(go.Bar(
            x=cat_stats["category"].apply(lambda c: c.split(" - ")[0]),
            y=cat_stats["fail_direct"],
            name="Không Tường lửa (FAIL %)",
            marker_color="#ef4444"
        ))
        fig_bar.add_trace(go.Bar(
            x=cat_stats["category"].apply(lambda c: c.split(" - ")[0]),
            y=cat_stats["fail_proxy"],
            name="Có Tường lửa (FAIL %)",
            marker_color="#10b981"
        ))
        fig_bar.update_layout(
            title="Tỷ lệ Bị khai thác (FAIL %) theo Từng nhóm OWASP",
            barmode="group",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(17,24,39,0.7)",
            font=dict(color="#e5e7eb"),
            yaxis=dict(title="% Thủng phòng thủ", range=[0, 105]),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with c_chart2:
        # Radar Chart: Mức độ Đề kháng An toàn (100% - Vulnerability Rate)
        safe_direct = [100 - v for v in cat_stats["fail_direct"]]
        safe_proxy = [100 - v for v in cat_stats["fail_proxy"]]
        labels = cat_stats["category"].apply(lambda c: c.split(" - ")[0]).tolist()

        fig_radar = go.Figure()
        fig_radar.add_trace(go.Scatterpolar(
            r=safe_direct + [safe_direct[0]],
            theta=labels + [labels[0]],
            fill="toself",
            name="Đề kháng khi KHÔNG có Tường lửa",
            line_color="#ef4444",
            fillcolor="rgba(239, 68, 68, 0.2)"
        ))
        fig_radar.add_trace(go.Scatterpolar(
            r=safe_proxy + [safe_proxy[0]],
            theta=labels + [labels[0]],
            fill="toself",
            name="Đề kháng khi CÓ Tường lửa Proxy",
            line_color="#10b981",
            fillcolor="rgba(16, 185, 129, 0.35)"
        ))
        fig_radar.update_layout(
            title="Biểu đồ Vùng Đề kháng An ninh (Robustness %)",
            polar=dict(
                radialaxis=dict(visible=True, range=[0, 100]),
                bgcolor="rgba(17,24,39,0.7)"
            ),
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e5e7eb"),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
        )
        st.plotly_chart(fig_radar, use_container_width=True)

    # 7. KHU VỰC 4: BẢNG SO SÁNH ĐỐI SOÁT CHI TIẾT (AUDIT DIFF TABLE)
    st.markdown("### 📋 Bảng Đối Soát Kết Quả Chi Tiết (Audit Diff)")
    show_df = df[["id", "category", "name", "status_direct", "status_proxy", "latency_direct", "latency_proxy"]]
    
    st.dataframe(
        show_df,
        column_config={
            "id": "Mã ID",
            "category": "Nhóm OWASP",
            "name": "Kịch bản Red Team",
            "status_direct": st.column_config.TextColumn("Kết quả (Baseline)", help="Khi không có tường lửa"),
            "status_proxy": st.column_config.TextColumn("Kết quả (Proxy)", help="Khi qua tường lửa"),
            "latency_direct": st.column_config.NumberColumn("Độ trễ Gốc (s)", format="%.3f"),
            "latency_proxy": st.column_config.NumberColumn("Độ trễ Proxy (s)", format="%.3f")
        },
        use_container_width=True,
        hide_index=True
    )

    # Xuất báo cáo khoa học
    csv_rep = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ XUẤT BÁO CÁO THỰC NGHIỆM ĐỐI CHỨNG (CSV)",
        csv_rep,
        "ab_benchmark_empirical_report.csv",
        "text/csv",
        use_container_width=True
    )
else:
    st.info("💡 Hãy nhấn nút **'BẮT ĐẦU CHẠY BENCHMARK ĐỐI CHỨNG'** ở trên để hệ thống tiến hành kiểm thử thực tế và tự động tính toán các chỉ số thống kê.")