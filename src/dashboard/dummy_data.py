# dummy_data.py
# 실제 JSON으로 교체할 때 이 파일만 수정하거나 load_data()를 바꾸면 됨

def get_dummy_data():
    return {
        "scan_target": "https://example.com",
        "scan_time": "2025-05-15 14:32:00",
        "headers": [
            {
                "name": "Content-Security-Policy",
                "alias": "CSP",
                "status": "missing",
                "risk": "High",
                "description": "XSS 공격으로 사용자 브라우저에서 악성 스크립트 실행 가능",
                "false_positive": False,
                "recommendation": "nginx.conf에 아래 헤더 추가:\nadd_header Content-Security-Policy \"default-src 'self'\";"
            },
            {
                "name": "Strict-Transport-Security",
                "alias": "HSTS",
                "status": "missing",
                "risk": "High",
                "description": "HTTP 다운그레이드 공격으로 암호화 통신 무력화 가능",
                "false_positive": False,
                "recommendation": "nginx.conf에 아래 헤더 추가:\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";"
            },
            {
                "name": "X-Frame-Options",
                "alias": "XFO",
                "status": "missing",
                "risk": "Medium",
                "description": "클릭재킹 공격으로 사용자 의도하지 않은 클릭 유도 가능",
                "false_positive": False,
                "recommendation": "nginx.conf에 아래 헤더 추가:\nadd_header X-Frame-Options \"DENY\";"
            },
            {
                "name": "Server",
                "alias": "Server",
                "status": "exposed",
                "risk": "Medium",
                "description": "서버 버전 정보 노출로 CVE 기반 타겟 공격 가능 (현재값: Apache/2.4.51)",
                "false_positive": False,
                "recommendation": "httpd.conf에서 아래 설정:\nServerTokens Prod\nServerSignature Off"
            },
            {
                "name": "X-Content-Type-Options",
                "alias": "XCTO",
                "status": "missing",
                "risk": "Low",
                "description": "브라우저가 MIME 타입을 임의 추측하여 악성 파일 실행 가능",
                "false_positive": False,
                "recommendation": "nginx.conf에 아래 헤더 추가:\nadd_header X-Content-Type-Options \"nosniff\";"
            },
            {
                "name": "X-Powered-By",
                "alias": "X-Powered-By",
                "status": "ok",
                "risk": "Low",
                "description": "헤더가 제거되어 있어 정상",
                "false_positive": False,
                "recommendation": "현재 설정 유지"
            },
        ]
    }