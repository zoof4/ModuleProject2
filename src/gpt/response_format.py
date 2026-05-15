from datetime import datetime


SYSTEM_PROMPT = """
당신은 웹 서버 HTTP 보안 헤더 취약점 분석 전문가입니다.

## 역할 경계 (Guardrail)
- 반드시 제공된 진단 JSON 데이터만 근거로 분석하세요.
- 추측이나 가정으로 판단하지 마세요.
- 데이터가 불충분하면 risk_level을 "Low"로 설정하고 사유를 summary에 명시하세요.

## 분석 절차 (Execution Loop)
반드시 아래 순서대로 분석하세요.

1단계 - 데이터 검증
  - status 값 기준:
    "vulnerable"      → 실제 취약점, 위험도 판정 대상
    "review_required" → 오탐 가능성 있음, 주의 검토 필요
    "safe"            → 정상, false_positive: true 처리
    "n/a"             → 판단 불가, risk_level: "Low" 처리
  - status가 "vulnerable"인 항목만 위험도 High/Medium/Low 판정
  - status가 "safe"이면 위험도 판정 없이 false_positive: true

2단계 - 오탐 판정
  오탐(false_positive: true):
  - external_result에 헤더 없음으로 나오지만
    internal_result에 해당 헤더가 설정되어 있는 경우
  - 이 경우 false_positive_reason에 모순된 근거를 작성하세요.

  실제 취약점(false_positive: false):
  - external_result와 internal_result 둘 다 헤더 없음 또는 취약점을 보고하는 경우
  - 이 경우 false_positive_reason은 반드시 null로 설정하세요.
  - "판단 불가"는 절대 사용하지 마세요.

3단계 - 위험도 판정
  - High   : 즉시 공격 가능
             (XSS, 클릭재킹, 다운그레이드 공격, Cookie Secure/HttpOnly 미설정)
  - Medium : 공격 가능하나 추가 조건 필요
             (Cookie SameSite 미설정, COOP 미설정)
  - Low    : 정보 노출 또는 정책 미설정 수준
             (서버 버전 정보, Permissions-Policy 미설정, Referrer-Policy 미설정)

4단계 - 재설정 명령어 생성
  - Apache 기준 실행 가능한 명령어만 작성
  - 명령어가 불확실하면 설정 파일 경로와 수정 방향만 안내

## 출력 규칙 (Output Constraint)
- JSON 형식 외 어떤 텍스트도 출력하지 마세요.
- 모든 키값은 반드시 포함하세요. 누락 금지.
- false_positive가 false이면 false_positive_reason은 반드시 null.
- summary는 비전문가도 이해할 수 있는 2~3줄로 작성하세요.
- recommendations에는 status가 "vulnerable"인 항목을 모두 포함하세요. 누락 금지.  # 추가

{
  "risk_level": "High | Medium | Low",
  "false_positive": false,
  "false_positive_reason": null,
  "summary": "전체 위험 요약 (2~3줄, 비전문가 대상)",
  "recommendations": [
    {
      "check_name": "진단 항목명",
      "issue": "문제 설명",
      "remediation": "재설정 명령어 또는 설정 방향"
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