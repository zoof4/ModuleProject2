import json
from datetime import datetime
from pathlib import Path

SYSTEM_PROMPT = """
당신은 '보안 전문 컨설턴트'입니다. 입력된 단순 진단 데이터를 바탕으로 전문 보고서를 작성하세요.

[분석 가이드라인]
1. 단순 복사 금지: 입력된 recommendation을 무시하고, 당신의 지식으로 훨씬 구체적인 가이드를 제공하십시오.
2. 실무 코드 포함: Nginx, Apache 등 실제 웹 서버 설정 파일에 들어갈 설정 문구(Directives)를 포함하십시오.
3. 공격 시나리오: 이 취약점을 방치했을 때 발생할 수 있는 실제 해킹 사례(클릭재킹, XSS 등)를 'issue'에 상세히 설명하십시오.
4. 모든 응답은 '한국어'로 작성하십시오.

[출력 형식]
{
  "risk_level": "High | Medium | Low",
  "summary": "GPT가 작성한 전체 요약",
  "false_positive": false,
  "false_positive_reason": null,
  "recommendations": [
    {
      "check_name": "진단 항목명",
      "issue": "공격 시나리오 기반의 상세 설명",
      "remediation": "서버별 설정 코드 및 해결 방법"
    }
  ],
  "recommendation_count": 1
}


def get_system_prompt():
    return SYSTEM_PROMPT

def format_gpt_response(raw_response: dict, target_info: dict) -> dict:
    """
    GPT의 응답을 받아서 서비스 표준 포맷으로 변환합니다. (검증 로직 포함)
    """
    # GPT가 응답을 누락했을 경우를 대비한 기본값 처리 (Safe-guard)
    formatted = {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "check_item": target_info.get("check_name", "Unknown"),
        "category": target_info.get("category", "General"),
        "analysis": {
            "risk_level": raw_response.get("risk_level", "Medium"),
            "false_positive": raw_response.get("false_positive", False),
            "false_positive_reason": raw_response.get("false_positive_reason"),
            "summary": raw_response.get("summary", "분석 내용을 생성할 수 없습니다."),
            "recommendations": raw_response.get("recommendations", [])
        }
    }
    return formatted

def save_result(formatted: dict, output_dir: str = "output") -> str:
    """분석 결과를 체계적인 파일명으로 저장합니다."""
    Path(output_dir).mkdir(exist_ok=True)
    item_name = formatted.get("check_item", "result").replace(" ", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/Report_{item_name}_{timestamp}.json"
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(formatted, f, ensure_ascii=False, indent=4)
    return filename
