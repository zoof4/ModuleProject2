import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path
from src.gpt.response_format import get_system_prompt, format_gpt_response

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

REQUIRED_KEYS = {"risk_level", "false_positive", "summary", "recommendations"}


def _call_gpt(messages: list) -> str:
    """GPT API 호출 후 content 문자열 반환"""
    response = client.chat.completions.create(
        model="gpt-5.2-pro",
        temperature=0,
        response_format={"type": "json_object"},  # type: ignore
        messages=messages  # type: ignore
    )
    return response.choices[0].message.content or ""


def _validate_and_retry(messages: list) -> dict:
    """GPT 호출 + 필수 키 검증 + 피드백 재시도"""
    for attempt in range(2):
        try:
            content = _call_gpt(messages)
            print(f"[디버그] attempt {attempt}")
            print(f"GPT 응답: {content}")
            result = json.loads(content)

            if not REQUIRED_KEYS.issubset(result.keys()):
                if attempt == 0:
                    messages.append(
                        {"role": "assistant", "content": content}
                    )
                    messages.append({
                        "role": "user",
                        "content": (
                            "응답에 필수 키가 누락됐습니다. "
                            "risk_level, false_positive, summary, "
                            "recommendations 모두 포함해서 다시 응답하세요."
                        )
                    })
                    continue
                return {"error": "GPT 응답 형식 오류 - 필수 키 누락"}

            return result

        except Exception as e:
            if attempt == 1:
                return {"error": str(e)}

    return {"error": "GPT 응답 실패"}


def analyze_scan_result(scan_result: dict) -> dict:
    """단일 진단 결과 dict를 GPT에 전달하고 분석 결과를 반환합니다."""
    messages = [
        {"role": "system", "content": get_system_prompt()},
        {
            "role": "user",
            "content": (
                "다음 HTTP 헤더 진단 결과를 분석하세요:\n"
                + json.dumps(scan_result, ensure_ascii=False, indent=2)
            )
        }
    ]
    return _validate_and_retry(messages)


def analyze_multiple_results(scan_results: list) -> dict:
    """다중 진단 결과 리스트를 GPT에 전달하고 분석 결과를 반환합니다."""
    messages = [
        {"role": "system", "content": get_system_prompt()},
        {
            "role": "user",
            "content": (
                "다음 HTTP 헤더 진단 결과 목록을 분석하세요:\n"
                + json.dumps(scan_results, ensure_ascii=False, indent=2)
            )
        }
    ]
    return _validate_and_retry(messages)


def load_scan_result(json_path: str) -> dict | list:
    """output/ 폴더의 JSON 파일을 읽어 반환합니다."""
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"파일 없음: {json_path}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "results" in data:
        return data["results"]

    return data


def run_analysis(json_path: str) -> dict:
    """Streamlit 대시보드 연동용 통합 함수."""
    scan_result = load_scan_result(json_path)
    if isinstance(scan_result, list):
        return analyze_multiple_results(scan_result)
    return analyze_scan_result(scan_result)