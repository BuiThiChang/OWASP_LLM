"""
FILE: pages/5_⚖️_AB_Benchmark.py
Mô tả: Phân hệ Benchmark đối chứng A/B (Baseline vs. AI Guardrail Proxy).
- Nạp kịch bản thực tế từ test_cases.py (Chuẩn OWASP 2026 A01 -> A10)
- Tự động thực thi đối chiếu 2 luồng: Trực tiếp (11436) vs. Qua Tường lửa (11435)
- Đo đạc chính xác độ trễ và tỷ lệ phòng vệ thực tế
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
from security_engine import evaluate_full_cycle, normalize_to_owasp_2026

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
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="benchmark-header">
    <div class="benchmark-title">⚖️ A/B BENCHMARK: ĐÁNH GIÁ ĐỊNH LƯỢNG HIỆU QUẢ TƯỜNG LỬA</div>
    <div style="opacity: 0.85; font-size: 0.95rem;">
        Kiểm thử đối chứng tự động giữa <b>Mô hình Trực tiếp (Baseline - Port 11436)</b> và <b>Mô hình có Tường lửa (Protected - Port 11435)</b>.
    </div>
</div>
""", unsafe_allow_html=True)

# Đồng bộ cả 2 luồng về chuẩn OpenAI API của Ollama
import os
OLLAMA_CORE_URL = os.getenv("OLLAMA_CORE_URL", "http://localhost:11436").rstrip("/")
DIRECT_OLLAMA_URL = f"{OLLAMA_CORE_URL}/v1/chat/completions"

PROXY_FIREWALL_URL = "http://localhost:11435/v1/chat/completions"
SECRET_KEY = "OWASP-LLM-TEST-2026-7F3A9C"

# 3. KHỞI TẠO SESSION STATE
if "benchmark_results" not in st.session_state:
    st.session_state.benchmark_results = None

# 4. KHU VỰC ĐIỀU KHIỂN
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

            short_code = cid.split("-")[0] if "-" in cid else normalize_to_owasp_2026(cid, cat)[0]

            status_info.markdown(f"⏳ Đang chạy kịch bản **[{idx+1}/{total_runs}]**: `{name}`...")

            # --- NHÁNH 1: GỬI TRỰC TIẾP OLLAMA (PORT 11436) ---
            t0 = time.time()
            text_direct = ""
            status_code_direct = 200
            try:
                r_direct = requests.post(DIRECT_OLLAMA_URL, json={
                    "model": target_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False
                }, timeout=120)
                lat_direct = round(time.time() - t0, 3)
                status_code_direct = r_direct.status_code
                
                if status_code_direct == 200:
                    r_json = r_direct.json()
                    text_direct = r_json.get("choices", [{}])[0].get("message", {}).get("content", "")
                else:
                    text_direct = f"Lỗi HTTP {status_code_direct}: {r_direct.text}"
            except Exception as e:
                lat_direct = round(time.time() - t0, 3)
                status_code_direct = 500
                text_direct = f"Lỗi kết nối Ollama Core: {str(e)}"

            verdict_direct, _ = evaluate_full_cycle(
                category_code=cat,
                prompt=prompt,
                response_text=text_direct,
                status_code=status_code_direct,
                secret=SECRET_KEY
            )
            # Nếu phản hồi rỗng hoặc lỗi kết nối thì không tính là PASS
            if status_code_direct != 200 or not text_direct.strip():
                verdict_direct = "ERROR"


            # --- NHÁNH 2: GỬI QUA TƯỜNG LỬA PROXY (PORT 11435) ---
            t1 = time.time()
            text_proxy = ""
            status_code_proxy = 200
            try:
                r_proxy = requests.post(PROXY_FIREWALL_URL, json={
                    "model": target_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False
                }, timeout=120)
                lat_proxy = round(time.time() - t1, 3)
                status_code_proxy = r_proxy.status_code
                
                if status_code_proxy == 200:
                    r_p_json = r_proxy.json()
                    text_proxy = r_p_json.get("choices", [{}])[0].get("message", {}).get("content", "")
                elif status_code_proxy == 403:
                    text_proxy = "[BLOCKED BY SECURITY FIREWALL]"
                else:
                    
                    text_proxy = f"Lỗi HTTP {status_code_proxy}: {r_proxy.text}"
            except Exception as e:
                lat_proxy = round(time.time() - t1, 3)
                status_code_proxy = 500
                text_proxy = f"Lỗi kết nối Proxy: {str(e)}"

            verdict_proxy, _ = evaluate_full_cycle(
                category_code=cat,
                prompt=prompt,
                response_text=text_proxy,
                status_code=status_code_proxy,
                secret=SECRET_KEY
            )
            # Lỗi HTTP (khác 200/403) hoặc phản hồi rỗng: không đủ căn cứ kết luận PASS/FAIL
            if status_code_proxy not in (200, 403) or not text_proxy.strip():
                verdict_proxy = "ERROR"

            records.append({
                "id": cid,
                "short_code": short_code,
                "category": cat,
                "name": name,
                "prompt": prompt,
                "status_direct": verdict_direct,
                "response_direct": text_direct,
                "latency_direct": lat_direct,
                "status_proxy": verdict_proxy,
                "response_proxy": text_proxy,
                "latency_proxy": lat_proxy
            })

            progress_bar.progress((idx + 1) / total_runs)

        status_info.success("🎉 Đã hoàn tất đối chứng toàn bộ kịch bản Red Team!")
        st.session_state.benchmark_results = pd.DataFrame(records)

st.divider()

# 5. KHU VỰC TÍNH TOÁN VÀ TRỰC QUAN HÓA
if st.session_state.benchmark_results is not None:
    df = st.session_state.benchmark_results
    valid = df[(df["status_direct"] != "ERROR") & (df["status_proxy"] != "ERROR")]
    errors = len(df) - len(valid)
    total_tests = len(valid)
    # Mọi chỉ số và biểu đồ chỉ tính trên các ca hợp lệ ("valid"), không tính ca lỗi hệ thống

    fail_direct = (valid["status_direct"] == "FAIL").sum()
    fail_proxy = (valid["status_proxy"] == "FAIL").sum()

    vuln_rate_direct = (fail_direct / total_tests * 100) if total_tests > 0 else 0
    vuln_rate_proxy = (fail_proxy / total_tests * 100) if total_tests > 0 else 0

    mitigated_count = len(valid[(valid["status_direct"] == "FAIL") & (valid["status_proxy"].isin(["BLOCKED", "PASS"]))])
    mitigation_rate = (mitigated_count / fail_direct * 100) if fail_direct > 0 else 100.0

    avg_lat_direct = valid["latency_direct"].mean() if total_tests > 0 else 0.0
    avg_lat_proxy = valid["latency_proxy"].mean() if total_tests > 0 else 0.0
    overhead_ms = max(0.0, (avg_lat_proxy - avg_lat_direct) * 1000)

    st.markdown("### 📊 Các Chỉ Số Định Lượng Thực Nghiệm (Live Calculated Metrics)")
    if errors > 0:
        st.warning(f"⚠️ Có {errors}/{len(df)} kịch bản gặp lỗi hệ thống (ERROR: mất kết nối Ollama/Proxy hoặc AI Judge không thẩm định được) và đã bị loại khỏi các chỉ số bên dưới.")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("TỔNG KỊCH BẢN THỬ NGHIỆM", f"{total_tests} Cases", delta=f"{errors} ca lỗi bị loại", delta_color="off")
    m2.metric("TỶ LỆ LỖ HỔNG (BASELINE)", f"{vuln_rate_direct:.1f}%", delta=f"{fail_direct}/{total_tests} ca phơi nhiễm", delta_color="inverse")
    m3.metric("TỶ LỆ LỖ HỔNG (CÓ PROXY)", f"{vuln_rate_proxy:.1f}%", delta=f"-{vuln_rate_direct - vuln_rate_proxy:.1f}% Rủi ro", delta_color="normal")
    # Không có ca nào bị khai thác ở baseline thì không có gì để "triệt tiêu" -> N/A, không ghi 100%
    m4.metric("HIỆU SUẤT TRIỆT TIÊU", f"{mitigation_rate:.1f}%" if fail_direct > 0 else "N/A", delta=f"Độ trễ trung bình +{overhead_ms:.1f}ms", delta_color="normal")

    st.write("")

    # BIỂU ĐỒ ĐỐI SÁNH
    if valid.empty:
        st.info("Không có kịch bản hợp lệ để dựng biểu đồ (tất cả đều ERROR). Kiểm tra kết nối Ollama rồi chạy lại.")
    else:
        c_chart1, c_chart2 = st.columns(2)

        with c_chart1:
            cat_stats = valid.groupby("short_code").apply(lambda x: pd.Series({
                "fail_direct": (x["status_direct"] == "FAIL").sum() / len(x) * 100,
                "fail_proxy": (x["status_proxy"] == "FAIL").sum() / len(x) * 100
            })).reset_index()

            fig_bar = go.Figure()
            fig_bar.add_trace(go.Bar(
                x=cat_stats["short_code"],
                y=cat_stats["fail_direct"],
                name="Không Tường lửa (FAIL %)",
                marker_color="#ef4444"
            ))
            fig_bar.add_trace(go.Bar(
                x=cat_stats["short_code"],
                y=cat_stats["fail_proxy"],
                name="Có Tường lửa (FAIL %)",
                marker_color="#10b981"
            ))
            fig_bar.update_layout(
                title="Tỷ lệ Bị khai thác (FAIL %) theo Mã OWASP 2026",
                barmode="group",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(17,24,39,0.7)",
                font=dict(color="#e5e7eb"),
                yaxis=dict(title="% Thủng phòng thủ", range=[0, 105]),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        with c_chart2:
            safe_direct = [100 - v for v in cat_stats["fail_direct"]]
            safe_proxy = [100 - v for v in cat_stats["fail_proxy"]]
            labels = cat_stats["short_code"].tolist()

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
                    radialaxis=dict(visible=True, range=[0, 100], tickfont=dict(color="#8b949e")),
                    angularaxis=dict(tickfont=dict(color="#e0e6ed")),
                    bgcolor="rgba(17,24,39,0.7)"
                ),
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e5e7eb"),
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_radar, use_container_width=True)

    # BẢNG SO SÁNH CHI TIẾT
    st.markdown("### 📋 Bảng Đối Soát Kết Quả Chi Tiết (Audit Diff)")
    show_df = df[["id", "category", "name", "status_direct", "status_proxy", "latency_direct", "latency_proxy"]]
    
    st.dataframe(
        show_df,
        column_config={
            "id": st.column_config.TextColumn("Mã ID", width="small"),
            "category": st.column_config.TextColumn("Nhóm OWASP 2026", width="medium"),
            "name": st.column_config.TextColumn("Kịch bản Red Team", width="medium"),
            "status_direct": st.column_config.TextColumn("Kết quả (Baseline)", help="Khi không có tường lửa"),
            "status_proxy": st.column_config.TextColumn("Kết quả (Proxy)", help="Khi qua tường lửa"),
            "latency_direct": st.column_config.NumberColumn("Độ trễ Gốc (s)", format="%.3f"),
            "latency_proxy": st.column_config.NumberColumn("Độ trễ Proxy (s)", format="%.3f")
        },
        use_container_width=True,
        hide_index=True
    )

    csv_rep = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ XUẤT BÁO CÁO THỰC NGHIỆM ĐỐI CHỨNG (CSV)",
        csv_rep,
        "ab_benchmark_empirical_report.csv",
        "text/csv",
        use_container_width=True
    )