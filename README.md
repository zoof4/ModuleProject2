# Header Hunter - HTTP 헤더 보안 자동 진단 플랫폼

SK 루키즈 AI_31기 5조 모듈 프로젝트

---

## 프로젝트 개요

웹 서버의 HTTP 헤더 취약점을 자동으로 탐지하고, GPT AI가 위험도를 판정하여
재설정 가이드를 제공하는 자동화 진단 시스템입니다.

- 기준: OWASP A02:2025 (Security Misconfiguration)
- 진단 대상: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Server 헤더

---

## 폴더 구조

```
ModuleProject2/
├── src/
│   ├── detection/          # 공격 탐지 스크립트
│   │   └── attack.py
│   ├── inspection/         # 서버 내부 파일/설정 확인
│   │   └── file_check.py
│   ├── gpt/                # GPT API 연동 및 응답 포맷
│   │   ├── api.py
│   │   └── response_format.py
│   └── dashboard/          # Streamlit 대시보드
├── output/                 # JSON 결과물 공유 폴더
├── docs/
├── test_gpt.py
├── requirements.txt
└── README.md
```

---

## 데이터 흐름

```
[테스트 서버 localhost]
        ↓
[attack.py + file_check.py] 스캔 후 JSON 생성
        ↓
  output/scan_result.json
        ↓
[api.py] JSON 읽어서 GPT 전달
        ↓
[response_format.py] GPT 응답 정제
        ↓
  result 딕셔너리
        ↓
[dashboard] Streamlit 화면 표시
```

---

## 환경 세팅

### 1. 레포 클론

```bash
git clone https://github.com/zoof4/ModuleProject2.git
cd ModuleProject2
```

### 2. 가상환경 세팅

```bash
python -m venv .venv
source .venv/Scripts/activate  # Windows Git Bash
pip install -r requirements.txt
```

### 3. .env 파일 생성

루트에 `.env` 파일을 생성하고 아래 내용을 입력합니다. (API Key는 팀장에게 요청)

```
OPENAI_API_KEY=sk-여기에_실제_키_입력
```

> `.env` 파일은 절대 GitHub에 올리지 마세요.

### 4. 브랜치 이동

```bash
git checkout -t origin/feature/본인브랜치명
```

---

## JSON 입출력 구조

### 입력 (attack.py + file_check.py 가 output/ 에 저장하는 형식)

단일 결과:

```json
{
  "check_name": "진단 항목명",
  "category": "A02:2025-Security Misconfiguration",
  "external_result": "외부 스캔 결과",
  "internal_result": "내부 설정 파일 분석 결과",
  "status": "Vulnerable",
  "risk_level": "High",
  "evidence": "취약점 근거",
  "recommendation": "조치 권고사항"
}
```

다중 결과 (리스트):

```json
[
  {
    "check_name": "...",
    "external_result": "...",
    "internal_result": "...",
    "status": "...",
    "risk_level": "...",
    "evidence": "...",
    "recommendation": "..."
  },
  {
    "check_name": "...",
    "external_result": "...",
    "internal_result": "...",
    "status": "...",
    "risk_level": "...",
    "evidence": "...",
    "recommendation": "..."
  }
]
```

> 단일 dict와 리스트 모두 자동 감지하여 처리합니다.

### 출력 (GPT 분석 결과)

```json
{
  "status": "success",
  "timestamp": "2026-05-15T11:47:59",
  "target": "http://localhost:108",
  "risk_level": "High",
  "false_positive": false,
  "false_positive_reason": null,
  "summary": "다수의 보안 헤더가 누락되어 있습니다.",
  "recommendations": [
    {
      "check_name": "진단 항목명",
      "issue": "문제 설명",
      "remediation": "재설정 명령어"
    }
  ],
  "recommendation_count": 3
}
```

---

## GPT 모듈 사용 방법 (대시보드 담당자용)

### 사용할 함수 3개

```python
# api.py
run_analysis(json_path, system_prompt)
# json_path     : output/ 폴더에 저장된 JSON 파일 경로
# system_prompt : get_system_prompt() 반환값 넣으면 됨

# response_format.py
get_system_prompt()
# 프롬프트 반환, run_analysis()에 그대로 넘기면 됨

format_gpt_response(raw, target_url)
# run_analysis() 결과를 대시보드용으로 정제
# target_url : 진단한 서버 URL
```

### 호출 순서

```python
from src.gpt.api import run_analysis
from src.gpt.response_format import get_system_prompt, format_gpt_response

prompt = get_system_prompt()
raw = run_analysis("output/scan_result.json", prompt)
result = format_gpt_response(raw, target_url="http://진단서버URL")
```

### result에서 꺼내 쓸 수 있는 값

```python
result["risk_level"]                        # "High" / "Medium" / "Low"
result["summary"]                           # 전체 요약 문자열
result["false_positive"]                    # True / False
result["false_positive_reason"]             # 오탐 근거 (오탐 아니면 null)
result["recommendation_count"]              # 권고사항 개수
result["recommendations"][0]["check_name"]  # 진단 항목명
result["recommendations"][0]["issue"]       # 문제 설명
result["recommendations"][0]["remediation"] # 재설정 명령어
```

### Streamlit 예시

```python
import streamlit as st

st.metric("위험도", result["risk_level"])
st.write(result["summary"])

for rec in result["recommendations"]:
    st.subheader(rec["check_name"])
    st.write(f"문제: {rec['issue']}")
    st.code(rec["remediation"])
```

---

## 브랜치 전략

```
main        ← 최종 완성본만 병합
  └── dev   ← 통합 테스트 브랜치 (PR 대상)
        ├── feature/attack-detection
        ├── feature/file-inspection
        ├── feature/gpt-api
        ├── feature/gpt-response
        └── feature/dashboard
```

### 작업 흐름

1. 본인 feature 브랜치에서 작업
2. 작업 완료 후 dev 브랜치로 PR 요청
3. 팀원 확인 후 dev에 merge
4. 최종 검증 완료 후 main으로 merge

---

## 기술 스택

| 구분      | 기술                 |
| --------- | -------------------- |
| 진단 환경 | Apache / PHP / MySQL |
| 진단 도구 | Python (requests)    |
| AI 분석   | OpenAI GPT-4o-mini   |
| 시각화    | Streamlit            |
| 버전 관리 | GitHub               |

---

## 주의사항

- `.env` 파일은 절대 커밋하지 마세요. (API Key 유출 위험)
- `output/` 폴더의 JSON 파일은 개인 테스트용으로만 사용하세요.
- 작업은 반드시 본인 feature 브랜치에서만 진행하세요.
- PR 전 반드시 본인 코드 테스트를 완료하세요.
