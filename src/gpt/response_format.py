import json
from datetime import datetime
from pathlib import Path

SYSTEM_PROMPT = """
당신은 '보안 전문 컨설턴트'입니다. 입력된 단순 진단 데이터를 바탕으로 전문 보고서를 작성하세요.
 
[분석 가이드라인]
1. 단순 복사 금지: 입력된 원본 데이터의 recommendation을 무시하고, 당신의 지식으로 훨씬 구체적인 가이드를 제공하십시오.
2. 데이터 복사 규칙(필수): 입력된 데이터의 'risk_level'과 'status'는 당신이 새로 평가하거나 바꾸지 마십시오. 반드시 입력 파일에 적힌 값을 그대로 복사해서 최종 출력물에 넣어야 합니다.
3. 구체적인 조치 절차 및 파일 경로 명시 (핵심):
    1단계를 remediation안에 반드시 꼭 필수로 포함해줘야 합니다. 조치 방안(remediation)을 작성할 때, 단순히 설정 코드만 던지지 마십시오. 설정을 수정하기 전에 선행되어야 하는 작업(예: 아파치 헤더 모듈 활성화 `a2enmod headers` 등)을 반드시 포함하십시오. 설정을 어느 파일(예: `/etc/apache2/conf-enabled/security.conf` 등)에 추가하거나 수정해야 하는지 정확한 파일 경로 및 가이드를 명시하십시오. 설정 적용 후 변경사항을 반영하기 위한 서비스 재시작 명령어(예: `service apache2 restart` 또는 `systemctl restart nginx`)까지 절차별(1단계, 2단계, 3단계)로 상세히 기술하십시오. 설정 코드에 대한 상세 설명(예: 각 옵션의 의미)도 함께 제공하십시오.
   remediation은 반드시 아래 형식으로 작성하십시오.
   
    
    
   ## 1단계: Apache 헤더 모듈 활성화
   아파치에서 응답 헤더를 조작하려면 headers 모듈을 반드시 먼저 켜야 합니다.
   
 
   a2enmod headers
 
   ## 2단계: security.conf 에 헤더 설정 적용
   conf-enabled 폴더안에 있는 security.conf 파일안에 헤더 규칙을 추가합니다.
 
   echo 'Header always set [헤더명] "[헤더값]"' >> /etc/apache2/conf-enabled/security.conf
 
   설정 상세 설명:
   - [각 옵션의 의미와 효과를 항목별로 설명]
 
   ## 3단계: 아파치 서비스 재시작
   변경된 설정 파일과 모듈을 서버에 적용합니다.
 
   service apache2 restart
 
   위 형식을 모든 항목에 반드시 적용하십시오. 단순 코드 나열 금지.
 
4. 공격 시나리오: 이 취약점을 방치했을 때 발생할 수 있는 실제 해킹 사례를 'issue'에 상세히 설명하십시오.
5. 모든 응답은 한국어로 작성하십시오.
6. status가 "vulnerable"인 항목을 모두 포함하세요. 누락 금지.
7. false_positive가 false이면 false_positive_reason은 반드시 null.

 
[출력 형식]
반드시 JSON 형식으로만 응답하세요. 다른 설명이나 텍스트는 절대 덧붙이지 마십시오.
{
  "risk_level": "입력 데이터에 적혀있는 risk_level 값을 그대로 복사 (High | Medium | Low)",
  "status": "입력 데이터에 적혀있는 status 값을 그대로 복사 (vulnerable | review_required | safe | n/a)",
  "summary": "GPT가 작성한 전체 요약",
  "false_positive": false,
  "false_positive_reason": null,
  "recommendations": [
    {
      "check_name": "진단 항목명",
      "issue": "공격 시나리오 기반의 상세 설명",
      "remediation": "위 형식(1단계~3단계)을 반드시 따르는 단계별 조치 가이드"
    }
  ]
}
"""
# 당신은 '보안 전문 컨설턴트'입니다. 입력된 단순 진단 데이터를 바탕으로 전문 보고서를 작성하세요.

# [분석 가이드라인]
# 1. 단순 복사 금지: 입력된 원본 데이터의 recommendation을 무시하고, 당신의 지식으로 훨씬 구체적인 가이드를 제공하십시오.
# 2. 데이터 복사 규칙(필수): 입력된 데이터의 'risk_level'과 'status'는 당신이 새로 평가하거나 바꾸지 마십시오. 반드시 입력 파일에 적힌 값을 그대로 복사해서 최종 출력물에 넣어야 합니다.
# 3. 구체적인 조치 절차 및 파일 경로 명시 (핵심): 
#    - 조치 방안(remediation)을 작성할 때, 단순히 설정 코드만 던지지 마십시오.
#    - 설정을 수정하기 전에 선행되어야 하는 작업(예: 아파치 헤더 모듈 활성화 `a2enmod headers` 등)을 반드시 포함하십시오.
#    - 설정을 어느 파일(예: `/etc/apache2/conf-enabled/security.conf` 등)에 추가하거나 수정해야 하는지 정확한 파일 경로 및 가이드를 명시하십시오.
#    - 설정 적용 후 변경사항을 반영하기 위한 서비스 재시작 명령어(예: `service apache2 restart` 또는 `systemctl restart nginx`)까지 절차별(1단계, 2단계, 3단계)로 상세히 기술하십시오.
#    - 설정 코드에 대한 상세 설명(예: 각 옵션의 의미)도 함께 제공하십시오.
# 4. 공격 시나리오: 이 취약점을 방치했을 때 발생할 수 있는 실제 해킹 사례를 'issue'에 상세히 설명하십시오.
# 5. 모든 응답은 한국어로 작성하십시오.
# 6. status가 "vulnerable"인 항목을 모두 포함하세요. 누락 금지.
# 7. false_positive가 false이면 false_positive_reason은 반드시 null.

# [출력 형식]
# 반드시 JSON 형식으로만 응답하세요. 다른 설명이나 텍스트는 절대 덧붙이지 마십시오.
# {
#   "risk_level": "입력 데이터에 적혀있는 risk_level 값을 그대로 복사 (High | Medium | Low)",
#   "status": "입력 데이터에 적혀있는 status 값을 그대로 복사 (vulnerable | review_required | safe | n/a)",
#   "summary": "GPT가 작성한 전체 요약",
#   "false_positive": false,
#   "false_positive_reason": null,
#   "recommendations": [
#     {
#       "check_name": "진단 항목명",
#       "issue": "공격 시나리오 기반의 상세 설명",
#       "remediation": "선행 작업, 수정할 파일 경로, 설정 문구, 서비스 재시작 명령어 및 코드 상세 설명을 포함한 단계별 조치 가이드"
#     }
#   ]
# }
# """


def get_system_prompt() -> str:
    """SYSTEM_PROMPT 반환"""
    return SYSTEM_PROMPT


def format_gpt_response(raw_response: dict, target_info: dict) -> dict:
    """GPT 응답을 대시보드용 표준 포맷으로 변환합니다."""
    if "error" in raw_response:
        return {
            "status": "error",
            "message": raw_response["error"],
            "timestamp": datetime.now().isoformat()
        }

    return {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "check_item": target_info.get("check_name", "Unknown"),
        "category": target_info.get("category", "General"),
        "analysis": {
            "risk_level": raw_response.get("risk_level", "Medium"),
            "false_positive": raw_response.get("false_positive", False),
            "false_positive_reason": raw_response.get(
                "false_positive_reason"
            ),
            "summary": raw_response.get(
                "summary", "분석 내용을 생성할 수 없습니다."
            ),
            "recommendations": raw_response.get("recommendations", [])
        }
    }


def save_result(formatted: dict, output_dir: str = "output") -> str:
    """분석 결과를 JSON 파일로 저장합니다."""
    Path(output_dir).mkdir(exist_ok=True)
    item_name = formatted.get("check_item", "result")
    # Windows 파일명 특수문자 제거
    for char in [':', '/', '\\', '*', '?', '"', '<', '>', '|']:
        item_name = item_name.replace(char, '_')
    item_name = item_name.replace(' ', '_')
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{output_dir}/Report_{item_name}_{timestamp}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(formatted, f, ensure_ascii=False, indent=4)
    print(f"저장 완료: {filename}")
    return filename