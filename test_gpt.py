from src.gpt.api import analyze_scan_result, load_scan_result, run_analysis
from src.gpt.response_format import get_system_prompt, format_gpt_response, save_result, get_risk_badge

mock_scan_result = [
    {
        "check_name": "Missing Security Header: Content-Security-Policy",
        "category": "A02:2025-Security Misconfiguration",
        "external_result": "Header Not Found",
        "internal_result": "CSP 설정 없음 확인됨",
        "status": "Vulnerable",
        "risk_level": "High",
        "evidence": "Content-Security-Policy header is missing. Risk of XSS and data injection attacks.",
        "recommendation": "적절한 Content-Security-Policy를 설정하세요."
    },
    {
        "check_name": "Missing Security Header: X-Frame-Options",
        "category": "A02:2025-Security Misconfiguration",
        "external_result": "Header Not Found",
        "internal_result": "X-Frame-Options 설정 없음 확인됨",
        "status": "Vulnerable",
        "risk_level": "Medium",
        "evidence": "X-Frame-Options header is missing. Clickjacking vulnerability suspected.",
        "recommendation": "X-Frame-Options 헤더를 DENY 또는 SAMEORIGIN으로 설정하세요."
    },
    {
        "check_name": "Server Banner Exposure",
        "category": "A02:2025-Security Misconfiguration",
        "external_result": "Detected: Apache/2.4.41 (Ubuntu)",
        "internal_result": "서버 버전 정보 노출 확인됨",
        "status": "Vulnerable",
        "risk_level": "Low",
        "evidence": "HTTP Response Header Server is revealing version info.",
        "recommendation": "ServerTokens를 Prod로, ServerSignature를 Off로 변경하세요."
    }
]

print("GPT API 호출 중...")
prompt = get_system_prompt()
raw = analyze_scan_result(mock_scan_result, prompt)
formatted = format_gpt_response(raw, target_url="http://example.com")

print(f"위험도: {get_risk_badge(formatted['risk_level'])}")
print(f"요약: {formatted['summary']}")
print(f"권고사항: {formatted['recommendation_count']}건")

save_result(formatted)