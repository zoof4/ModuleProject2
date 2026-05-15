from src.gpt.api import analyze_scan_result, load_scan_result, run_analysis
from src.gpt.response_format import get_system_prompt, format_gpt_response, save_result, get_risk_badge

mock_scan_result = {
    "check_name": "Missing Security Header: Content-Security-Policy",
    "category": "A02:2025-Security Misconfiguration",
    "external_result": "Header Not Found",
    "internal_result": "CSP 설정 없음 확인됨",
    "status": "Vulnerable",
    "risk_level": "High",
    "evidence": "Content-Security-Policy header is missing. Risk of XSS and data injection attacks.",
    "recommendation": "적절한 Content-Security-Policy를 설정하여 신뢰할 수 있는 스크립트만 실행되도록 제한하세요."
}

print("GPT API 호출 중...")
prompt = get_system_prompt()
raw = analyze_scan_result(mock_scan_result, prompt)
formatted = format_gpt_response(raw, target_url="http://example.com")

print(f"위험도: {get_risk_badge(formatted['risk_level'])}")
print(f"요약: {formatted['summary']}")
print(f"권고사항: {formatted['recommendation_count']}건")

save_result(formatted)