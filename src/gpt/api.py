import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def analyze_scan_result(scan_result: dict, system_prompt: str) -> dict:
    """단일 진단 결과 dict를 GPT에 전달하고 분석 결과를 반환합니다."""
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
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ]
        )
        content = response.choices[0].message.content or ""
        return json.loads(content)

    except Exception as e:
        return {"error": str(e)}


def analyze_multiple_results(scan_results: list, system_prompt: str) -> dict:
    """다중 진단 결과 리스트를 GPT에 전달하고 분석 결과를 반환합니다."""
    user_message = (
        f"다음 HTTP 헤더 진단 결과 목록을 분석하세요:\n"
        f"{json.dumps(scan_results, ensure_ascii=False, indent=2)}"
    )

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.1,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ]
        )
        content = response.choices[0].message.content or ""
        return json.loads(content)

    except Exception as e:
        return {"error": str(e)}


def load_scan_result(json_path: str) -> dict | list:
    """output/ 폴더의 JSON 파일을 읽어 반환합니다."""
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"파일 없음: {json_path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_analysis(json_path: str, system_prompt: str) -> dict:
    """
    Streamlit 대시보드 연동용 통합 함수.
    단일 dict 또는 리스트를 자동 감지하여 처리합니다.
    """
    scan_result = load_scan_result(json_path)

    if isinstance(scan_result, list):
        return analyze_multiple_results(scan_result, system_prompt)
    return analyze_scan_result(scan_result, system_prompt)