# src/gpt/response_format.py
import json
from pathlib import Path
from datetime import datetime


def format_gpt_response(raw_response: dict, target_url: str = "") -> dict:
    """
    GPT 응답을 대시보드용 표준 포맷으로 변환합니다.
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


def save_result(formatted: dict, output_dir: str = "output") -> str:
    """분석 결과를 JSON 파일로 저장합니다."""
    Path(output_dir).mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/gpt_result_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(formatted, f, ensure_ascii=False, indent=2)
    print(f"저장 완료: {filename}")
    return filename


def get_risk_badge(risk_level: str) -> str:
    """위험도 텍스트 배지 반환 (대시보드 연동용)"""
    badges = {
        "High":   "[HIGH   - 즉시 조치 필요]",
        "Medium": "[MEDIUM - 조치 권고]",
        "Low":    "[LOW    - 모니터링]"
    }
    return badges.get(risk_level, "[UNKNOWN]")