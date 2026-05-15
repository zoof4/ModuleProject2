import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def analyze_scan_result(scan_result: dict, system_prompt: str) -> dict:
    """
    진단 JSON을 GPT에 전달하고 분석 결과를 반환합니다.

    Args:
        scan_result: {
            "check_name": str,
            "category": str,
            "external_result": str,
            "internal_result": str,
            "status": str,
            "risk_level": str,
            "evidence": str,
            "recommendation": str
        }
        system_prompt: response_format.py의 get_system_prompt() 반환값

    Returns:
        GPT 분석 결과 dict
    """
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


def load_scan_result(json_path: str) -> dict:
    """
    output/ 폴더의 JSON 파일을 읽어 반환합니다.

    Args:
        json_path: JSON 파일 경로 (예: output/scan_result.json)

    Returns:
        진단 결과 dict
    """
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"파일 없음: {json_path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_analysis(json_path: str, system_prompt: str) -> dict:
    """
    Streamlit 대시보드 연동용 통합 함수.

    Args:
        json_path: output/ 폴더 내 JSON 파일 경로
        system_prompt: response_format.py의 get_system_prompt() 반환값

    Returns:
        GPT 분석 결과 dict
    """
    scan_result = load_scan_result(json_path)
    return analyze_scan_result(scan_result, system_prompt)