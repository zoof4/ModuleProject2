from datetime import datetime


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
      "check_name": "진단 항목명",
      "issue": "문제 설명",
      "remediation": "재설정 명령어 또는 설정값"
    }
  ]
}
"""


def get_system_prompt() -> str:
    """프롬프트 담당자가 관리하는 SYSTEM_PROMPT 반환"""
    return SYSTEM_PROMPT


def format_gpt_response(raw_response: dict, target_url: str = "") -> dict:
    """
    GPT 응답을 대시보드용 표준 포맷으로 변환합니다.

    Args:
        raw_response: analyze_scan_result() 반환값
        target_url: 진단 대상 URL

    Returns:
        표준화된 결과 dict
    """
    if "error" in raw_response:
        return {
            "status": "error",
            "message": raw_response["error"],
            "timestamp": datetime.now().isoformat()
        }

    return {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "risk_level": raw_response.get("risk_level", "Unknown"),
        "false_positive": raw_response.get("false_positive", False),
        "false_positive_reason": raw_response.get("false_positive_reason"),
        "summary": raw_response.get("summary", ""),
        "recommendations": raw_response.get("recommendations", []),
        "recommendation_count": len(raw_response.get("recommendations", []))
    }


def get_risk_badge(risk_level: str) -> str:
    """위험도 텍스트 배지 반환 (대시보드 연동용)"""
    badges = {
        "High":   "[HIGH   - 즉시 조치 필요]",
        "Medium": "[MEDIUM - 조치 권고]",
        "Low":    "[LOW    - 모니터링]"
    }
    return badges.get(risk_level, "[UNKNOWN]")


def save_result(formatted: dict, output_dir: str = "output") -> str:
    """분석 결과를 JSON 파일로 저장합니다."""
    import json
    from pathlib import Path

    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/gpt_result_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(formatted, f, ensure_ascii=False, indent=2)
    print(f"저장 완료: {filename}")
    return filename