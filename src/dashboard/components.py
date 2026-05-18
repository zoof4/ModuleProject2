# components.py
# 각 UI 섹션을 함수로 분리 - 필요한 것만 골라서 app.py에서 호출

import streamlit as st
import pandas as pd
import plotly.express as px

RISK_COLOR = {
    "High":   "#ef4444",
    "Medium": "#f97316",
    "Low":    "#eab308",
    "ok":     "#22c55e",
}

STATUS_LABEL = {
    "vulnerable":      "🔴 취약",
    "safe":            "🟢 양호",
    "review_required": "🟡 검토필요",
    "n/a":             "⚫ 해당없음",
}


def render_summary(summary: dict):
    """상단 요약 카드"""
    st.markdown("## 📊 스캔 요약")
    st.caption(f"대상: `{summary['scan_target']}`  |  스캔 시각: {summary['scan_time']}")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("전체 헤더", summary["total"])
    col2.metric("이슈 있음", summary["issue_count"], delta=f"-{summary['issue_count']}", delta_color="inverse")
    col3.metric("정상", summary["ok_count"])
    col4.metric("High 위험", summary["risk_count"]["High"])


def render_risk_chart(summary: dict):
    """위험도 도넛 차트"""
    st.markdown("### 위험도 분포")
    rc = summary["risk_count"]
    df = pd.DataFrame({
        "등급": [k for k, v in rc.items() if v > 0],
        "개수": [v for v in rc.values() if v > 0]
    })
    if df.empty:
        st.info("진단 결과가 없습니다.")
        return
    fig = px.pie(
        df, names="등급", values="개수", hole=0.55,
        color="등급",
        color_discrete_map={
            "High":   "#ef4444",
            "Medium": "#f97316",
            "Low":    "#eab308",
            "양호":   "#22c55e"
        }
    )
    fig.update_layout(
        margin=dict(t=0, b=0, l=0, r=0),
        height=280,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#cccccc"),
        legend=dict(font=dict(color="#aaaaaa")),
    )
    fig.update_traces(textfont_color="#ffffff")
    st.plotly_chart(fig, use_container_width=True)


def render_header_table(headers: list):
    """헤더별 진단 결과 테이블"""
    st.markdown("### 📋 헤더별 진단 결과")

    rows = []
    for h in headers:
        rows.append({
            "헤더": h["name"],
            "상태": STATUS_LABEL.get(h["status"], h["status"]),
            "위험도": h["risk"],
            "설명": h["description"],
        })

    df = pd.DataFrame(rows)

    def color_risk(val):
        color = RISK_COLOR.get(val, "gray")
        return f"color: {color}; font-weight: bold"

    st.dataframe(
        df.style.map(color_risk, subset=["위험도"]),
        use_container_width=True,
        hide_index=True,
    )


def render_detail_cards(headers: list):
    """헤더별 상세 카드 (대응방안 포함)"""
    st.markdown("### 🛠️ 대응방안 상세")

    issue_headers = [h for h in headers if h["status"] != "ok"]
    if not issue_headers:
        st.success("모든 헤더가 정상입니다!")
        return

    for h in issue_headers:
        color = RISK_COLOR.get(h["risk"], "gray")
        with st.expander(f"{STATUS_LABEL.get(h['status'])} **{h['name']}** — :{h['risk']}"):
            st.markdown(f"**위험도:** <span style='color:{color}'>**{h['risk']}**</span>", unsafe_allow_html=True)
            st.markdown(f"**위협 설명:** {h['description']}")
            st.markdown("**권장 조치:**")
            st.markdown(h["recommendation"])
            if h.get("false_positive"):
                st.warning("⚠️ 오탐 가능성 있음 - GPT 판단 결과를 확인하세요")