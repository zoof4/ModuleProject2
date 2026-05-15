import json
import os

os.makedirs('output', exist_ok=True)
sample = {
    "check_name": "X-Frame-Options Header",
    "category": "OWASP A05",
    "status": "Fail",
    "risk_level": "High",
    "evidence": "X-Frame-Options header missing",
    "recommendation": "Set to SAMEORIGIN"
}

with open('output/test_result.json', 'w', encoding='utf-8') as f:
    json.dump(sample, f, indent=4)
print("✅ 샘플 데이터 준비 완료")