# pdf다운로드
from fpdf import FPDF
from fpdf.fonts import FontFace
import plotly.express as px
import plotly.io as pio
import pandas as pd
import tempfile, os

MALGUN      = "C:/Windows/Fonts/malgun.ttf"
MALGUN_BOLD = "C:/Windows/Fonts/malgunbd.ttf"

class PDF(FPDF):
    def __init__(self):
        super().__init__()
        self.add_font("MalgunGothic", "",  MALGUN)
        self.add_font("MalgunGothic", "B", MALGUN_BOLD)

    def header(self):
        self.set_font("MalgunGothic", "B", 14)
        self.set_text_color(0, 0, 0)
        self.cell(0, 14, "Header Hunter - 진단 리포트", align="C", ln=True)
        self.ln(2)

    def footer(self):
        self.set_y(-12)
        self.set_font("MalgunGothic", "", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

RISK_COLOR = {
    "High":   (239, 68,  68),
    "Medium": (249, 115, 22),
    "Low":    (234, 179,  8),
}

STATUS_LABEL = {
    "missing": "누락",
    "exposed": "노출",
    "ok":      "정상",
}

def _make_chart_image(headers: list) -> str:
    rc = {"High": 0, "Medium": 0, "Low": 0}
    for h in headers:
        if h["status"] != "ok":
            rc[h["risk"]] = rc.get(h["risk"], 0) + 1

    df = pd.DataFrame({"등급": list(rc.keys()), "개수": list(rc.values())})
    fig = px.pie(
        df, names="등급", values="개수", hole=0.5,
        color="등급",
        color_discrete_map={"High": "#ef4444", "Medium": "#f97316", "Low": "#eab308"}
    )
    fig.update_layout(
        paper_bgcolor="white", plot_bgcolor="white",
        font=dict(color="black"),
        margin=dict(t=20, b=20, l=20, r=20),
        height=300, width=300,
    )
    tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    pio.write_image(fig, tmp.name, format="png")
    return tmp.name

def export_pdf(data: dict, options: dict) -> bytes:
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    headers = data.get("headers", [])

    # ── 1. 요약 ───────────────────────────────────────────
    if options.get("summary"):
        pdf.set_font("MalgunGothic", "B", 12)
        pdf.cell(0, 8, "[ 스캔 요약 ]", ln=True)
        pdf.set_font("MalgunGothic", "", 12)
        pdf.cell(0, 6, f"대상  : {data.get('scan_target', '-')}", ln=True)
        pdf.cell(0, 6, f"시각  : {data.get('scan_time', '-')}", ln=True)
        total = len(headers)
        issues = sum(1 for h in headers if h["status"] != "ok")
        high   = sum(1 for h in headers if h["risk"] == "High"   and h["status"] != "ok")
        medium = sum(1 for h in headers if h["risk"] == "Medium" and h["status"] != "ok")
        low    = sum(1 for h in headers if h["risk"] == "Low"    and h["status"] != "ok")
        pdf.cell(0, 6, f"전체 헤더 : {total}  |  이슈 : {issues}  |  High : {high}  Medium : {medium}  Low : {low}", ln=True)
        pdf.ln(4)

    # ── 2. 차트 ───────────────────────────────────────────
    if options.get("chart"):
        pdf.set_font("MalgunGothic", "B", 12)
        pdf.cell(0, 8, "[ 위험도 분포 ]", ln=True)
        try:
            chart_path = _make_chart_image(headers)
            pdf.image(chart_path, x=55, w=80)
            os.unlink(chart_path)
        except Exception as e:
            pdf.cell(0, 6, f"차트 생성 실패: {e}", ln=True)
        pdf.ln(4)

    # ── 3. 테이블 (배경색 문제 해결 버전) ───────────────────────
    if options.get("table"):
        pdf.set_font("MalgunGothic", "B", 12)
        pdf.cell(0, 8, "[ 헤더별 진단 결과 ]", ln=True)

        # 헤더 전용 스타일
        header_style = FontFace(fill_color=(220, 220, 220), emphasis="BOLD")

        with pdf.table(
            borders_layout="ALL",
            cell_fill_mode="NONE",
            col_widths=(45, 20, 20, 105),
            line_height=7,
            headings_style=header_style
        ) as table:
            h_row = table.row()
            h_row.cell("헤더")
            h_row.cell("상태")
            h_row.cell("위험도")
            h_row.cell("설명")

            # 데이터 행
            pdf.set_font("MalgunGothic", "", 10)
            for h in headers:
                row = table.row()
                row.cell(h["name"])
                row.cell(STATUS_LABEL.get(h["status"], h["status"]))
                
                # 위험도 색상설정
                r, g, b = RISK_COLOR.get(h["risk"], (0, 0, 0))
                pdf.set_text_color(r, g, b)
                row.cell(h["risk"])
                
                # 설명
                pdf.set_text_color(0, 0, 0)
                row.cell(h["description"])
        pdf.ln(4)

    # ── 4. 대응방안 ───────────────────────────────────────
    if options.get("detail"):
        pdf.set_font("MalgunGothic", "B", 12)
        pdf.cell(0, 8, "[ 대응방안 상세 ]", ln=True)
        for h in [h for h in headers if h["status"] != "ok"]:
            r, g, b = RISK_COLOR.get(h["risk"], (0, 0, 0))
            pdf.set_font("MalgunGothic", "B", 12)
            pdf.set_text_color(r, g, b)
            pdf.cell(0, 7, f"{h['name']}  [{h['risk']}]", ln=True)
            pdf.set_font("MalgunGothic", "", 12)
            pdf.set_text_color(0, 0, 0)
            pdf.set_x(10)
            pdf.multi_cell(190, 6, f"위협: {h['description']}")
            pdf.set_x(10)
            pdf.multi_cell(190, 6, "조치:")
            pdf.set_font("MalgunGothic", "", 10)
            pdf.set_text_color(60, 60, 60)
            for line in h['recommendation'].split("\n"):
                pdf.set_x(10)
                pdf.multi_cell(190, 5, line if line.strip() else " ")
            pdf.ln(3)

    return bytes(pdf.output())