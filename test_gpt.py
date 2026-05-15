import json
from src.gpt.api import analyze_headers
from src.gpt.response_format import format_gpt_response, save_result, get_risk_badge

mock_scan_result = {
    "target_url": "http://example.com",
    "missing_headers": [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options"
    ],
    "exposed_headers": {
        "Server": "Apache/2.4.51 (Ubuntu)",
        "X-Powered-By": "PHP/8.0.12"
    },
    "present_headers": [
        "X-Content-Type-Options"
    ]
}

print("GPT API 호출 중...")
raw = analyze_headers(mock_scan_result)
formatted = format_gpt_response(raw, target_url="http://example.com")

print(f"위험도: {get_risk_badge(formatted['risk_level'])}")
print(f"요약: {formatted['summary']}")
print(f"권고사항: {formatted['recommendation_count']}건")

save_result(formatted)