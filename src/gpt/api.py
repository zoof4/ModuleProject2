import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """
당신은 웹 서버 HTTP 보안 헤더 취약점 분석 전문가입니다.
진단 결과 JSON을 받아 아래 형식으로만 응답하세요. JSON 외 다른 텍스트는 출력하지 마세요.

{
  "risk_level": "High | Medium | Low",
  "false_positive": true,
  "false_positive_reason": "오탐 판단 근거 (오탐이 아닐 경우 null)",
  "summary": "전체 위험 요약 (2~3줄)",
  "recommendations": [
    {
      "header": "헤더명",
      "issue": "문제 설명",
      "remediation": "재설정 명령어 또는 설정값"
    }
  ]
}
"""


def analyze_headers(scan_result: dict) -> dict:
    user_message = (
        f"다음 HTTP 헤더 진단 결과를 분석하세요:\n"
        f"{json.dumps(scan_result, ensure_ascii=False, indent=2)}"
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.1,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message}
            ]
        )
        content = response.choices[0].message.content or ""
        return json.loads(content)

    except Exception as e:
        return {"error": str(e)}


def load_scan_result(json_path: str) -> dict:
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"파일 없음: {json_path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)