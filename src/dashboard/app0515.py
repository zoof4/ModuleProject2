# app.py
# streamlit run app.py 로 실행

import streamlit as st
from data_loader import load_data, get_summary
from components import (
    render_summary,
    render_risk_chart,
    render_header_table,
    render_detail_cards,
)

# ── 페이지 기본 설정 ──────────────────────────────────────
st.set_page_config(
    page_title="Header Hunter",
    page_icon="🎯",
    layout="wide",
)

st.title("🎯 Header Hunter 대시보드")
st.markdown("웹 서버 HTTP 보안 헤더 자동 진단 결과")
st.divider()

# ── 데이터 로드 ───────────────────────────────────────────
# 실제 JSON 연동 시: load_data("../output/result.json")
data = load_data()
summary = get_summary(data)
headers = data["headers"]

# ── 레이아웃 ─────────────────────────────────────────────
render_summary(summary)

st.divider()

col_left, col_right = st.columns([1, 2])
with col_left:
    render_risk_chart(summary)
with col_right:
    render_header_table(headers)

st.divider()

render_detail_cards(headers)

# ── PDF 다운로드 (추후 구현 자리) ─────────────────────────
st.divider()
st.markdown("### 📄 PDF 리포트 다운로드")
st.info("PDF 다운로드 기능은 추후 구현 예정입니다. (fpdf2 또는 reportlab 사용 예정)")
# TODO: pdf_exporter.py 모듈 추가 후 아래 버튼 활성화
# if st.button("PDF 다운로드"):
#     from pdf_exporter import export_pdf
#     export_pdf(data)
