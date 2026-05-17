# app.py
# streamlit run app.py 로 실행

import streamlit as st
import os
import sys
import subprocess  # 👈 [추가] 백엔드 스크립트 자동 가동을 위한 모듈
import time

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))

if project_root not in sys.path:
    sys.path.append(project_root)

from data_loader import load_data, get_summary
from components import (
    render_summary,
    render_risk_chart,
    render_header_table,
    render_detail_cards,
)

# 🚀 [추가] 두 분의 백엔드 스크립트 절대 경로 정의
DETECT_SCRIPT = os.path.join(project_root, "src", "detection", "attack-detection.py")
FILE_CHECK_SCRIPT = os.path.join(project_root, "src", "inspection", "file_check.py")

st.set_page_config(
    page_title="Header Hunter",
    page_icon="🎯",
    layout="wide",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;600&display=swap');

.stApp {
    background-color: #0d0d0d;
    color: #e0e0e0;
    font-family: 'Inter', sans-serif;
}
section[data-testid="stSidebar"] { background-color: #111111; }

h1 {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 1.6rem !important;
    color: #ffffff !important;
    letter-spacing: -0.5px;
}
h2, h3 {
    font-family: 'Inter', sans-serif !important;
    color: #cccccc !important;
    font-weight: 600 !important;
}

input[type="text"] {
    background-color: #1a1a1a !important;
    color: #e0e0e0 !important;
    border: 1px solid #333 !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
}
input[type="text"]:focus { border-color: #555 !important; }

.stButton > button {
    background-color: #1a1a1a !important;
    color: #e0e0e0 !important;
    border: 1px solid #444 !important;
    border-radius: 6px !important;
    font-weight: 600 !important;
    transition: all 0.15s ease;
}
.stButton > button:hover {
    background-color: #2a2a2a !important;
    border-color: #666 !important;
    color: #ffffff !important;
}

[data-testid="stMetric"] {
    background-color: #141414 !important;
    border: 1px solid #222 !important;
    border-radius: 8px !important;
    padding: 16px !important;
}
[data-testid="stMetricLabel"] { color: #888 !important; font-size: 0.75rem !important; }
[data-testid="stMetricValue"] { color: #ffffff !important; font-family: 'JetBrains Mono', monospace !important; }

details {
    background-color: #141414 !important;
    border: 1px solid #222 !important;
    border-radius: 8px !important;
    margin-bottom: 8px !important;
}
summary { color: #cccccc !important; }

[data-testid="stDataFrame"] {
    border: 1px solid #222 !important;
    border-radius: 8px !important;
}

hr { border-color: #222 !important; }

[data-testid="stAlert"] {
    background-color: #141414 !important;
    border-radius: 6px !important;
    border: 1px solid #333 !important;
}

code, pre {
    background-color: #1a1a1a !important;
    color: #a8d8a8 !important;
    font-family: 'JetBrains Mono', monospace !important;
    border-radius: 4px !important;
}
            
#MainMenu {visibility: hidden;}

header {visibility: hidden;}

footer {visibility: hidden;}

.block-container {
    padding-top: 2rem;
}
</style>
""", unsafe_allow_html=True)

st.markdown("# 🎯 Header Hunter")
st.markdown("<p style='color:#666; font-size:0.85rem; margin-top:-12px;'>HTTP 보안 헤더 자동 진단 플랫폼</p>", unsafe_allow_html=True)
st.divider()

col_url, col_btn = st.columns([5, 1])
with col_url:
    url_input = st.text_input(
        label="URL",
        placeholder="https://example.com",
        label_visibility="collapsed"
    )
with col_btn:
    scan_clicked = st.button("스캔 시작 →", use_container_width=True)

if scan_clicked:
    if url_input:
        # 🕹️ [기능 삽입] 버튼 클릭 시 백엔드 스크립트 2개를 순서대로 가동 (입력된 url_input 전달)
        with st.spinner("🔍 진단 스크립트 자동 실행 중..."):
            try:
                # 1. 내 웹 어택 탐지 파일 실행
                st.toast("⏳ 1단계: 내 보안 진단 스크립트 실행 중...")
                subprocess.run(["python", DETECT_SCRIPT, url_input], check=True)
                
                # 2. 동준님 점검 파일 실행
                st.toast("⏳ 2단계: 동준님 설정 점검 스크립트 실행 중...")
                subprocess.run(["python", FILE_CHECK_SCRIPT, url_input], check=True)
                
                st.toast("✅ 스크립트 점검 완료! GPT 분석으로 진입합니다.")
            except subprocess.CalledProcessError:
                st.error("❌ 스크립트 자동 가동 중 오류가 발생했습니다. 경로 및 터미널 권한을 확인하세요.")

        # ----------------- 여기서부터는 기존 오리지널 코드와 100% 동일 -----------------
        json_path = "output/internal_inspection_result_latest.json"
        if os.path.exists(json_path):
            with st.spinner("GPT 분석 중..."):
                from src.gpt.api import run_analysis
                from src.gpt.response_format import format_gpt_response
                from data_loader import convert_backend_json
                import json as _json

                raw = run_analysis(json_path)

                with open(json_path, encoding="utf-8") as f:
                    scan_data = _json.load(f)
                target_info = scan_data[0]  # 리스트 구조

                formatted = format_gpt_response(raw, target_info)
                converted = convert_backend_json(formatted, scan_data)
                converted["scan_target"] = url_input
                st.session_state["data"] = converted
        else:
            st.warning("output/internal_inspection_result_latest.json 파일이 없습니다. 진단 스크립트를 먼저 실행해주세요.")
    else:
        st.warning("URL을 입력해주세요.")

st.divider()

# 스캔 결과 있으면 사용, 없으면 더미 데이터
data = st.session_state.get("data") or load_data()
summary = get_summary(data)
headers = data["headers"]

# GPT 요약 있으면 표시
if data.get("gpt_summary"):
    st.info(f"🤖 GPT 요약: {data['gpt_summary']}")

render_summary(summary)
st.divider()

col_left, col_right = st.columns([1, 2])
with col_left:
    render_risk_chart(summary)
with col_right:
    render_header_table(headers)

st.divider()
render_detail_cards(headers)

st.divider()
st.markdown("### 📄 PDF 리포트")

col_a, col_b, col_c, col_d = st.columns(4)
with col_a:
    opt_summary = st.checkbox("요약", value=False)
with col_b:
    opt_chart   = st.checkbox("위험도 차트", value=False)
with col_c:
    opt_table   = st.checkbox("진단 결과 테이블", value=False)
with col_d:
    opt_detail  = st.checkbox("대응방안 상세", value=False)

from pdf_exporter import export_pdf
if any([opt_summary, opt_chart, opt_table, opt_detail]):
    pdf_bytes = export_pdf(data, {
        "summary": opt_summary,
        "chart":   opt_chart,
        "table":   opt_table,
        "detail":  opt_detail,
    })
    st.download_button(
        label="📥 PDF 다운로드",
        data=pdf_bytes,
        file_name="header_hunter_report.pdf",
        mime="application/pdf",
    )
else:
    st.button("📥 PDF 다운로드", disabled=True)