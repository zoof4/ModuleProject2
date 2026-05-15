import requests
import json
from datetime import datetime

class ExternalScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.category_2025 = "A02:2025-Security Misconfiguration"
        
        # [수정 1] 서버에 접속해서 헤더를 미리 가져와야 합니다.
        try:
            response = requests.get(self.target_url, timeout=5)
            self.headers = response.headers
        except Exception as e:
            print(f"서버 접속 오류: {e}")
            self.headers = {}

    # [수정 2] 모든 진단을 실행하는 '작업 반장' 함수를 추가했습니다.
    def run_scan(self):
        results = []
        if not self.headers:
            return results

        # 실행할 진단 함수 리스트
        check_functions = [
            self._check_server_banner,
            self._check_x_frame_options,
            self._check_x_content_type_options,
            self._check_hsts,
            self._check_csp
        ]
        
        for func in check_functions:
            result = func(self.headers)
            if result:
                results.append(result)
        
        return results

    # 진단 모듈 1 - Server 헤더
    def _check_server_banner(self, headers):
        server_banner = headers.get("Server")
        if server_banner:
            return {
                "check_name": "Server Banner Exposure",
                "category": self.category_2025,
                "external_result": f"Detected: {server_banner}",
                "internal_result": "",
                "status": "Vulnerable",
                "risk_level": "Low",
                "evidence": f"HTTP Response Header 'Server' is revealing version info: {server_banner}",
                "recommendation": "설정 파일에서 ServerTokens를 'Prod'로, ServerSignature를 'Off'로 변경하세요."
            }
        return None

    # 진단 모듈 2 - X-Frame-Options
    def _check_x_frame_options(self, headers):
        if "X-Frame-Options" not in headers:
            return {
                "check_name": "Missing Security Header: X-Frame-Options",
                "category": self.category_2025,
                "external_result": "Header Not Found",
                "internal_result": "",
                "status": "Vulnerable",
                "risk_level": "Medium",
                "evidence": "X-Frame-Options header is missing. Clickjacking vulnerability suspected.",
                "recommendation": "X-Frame-Options 헤더를 'DENY' 또는 'SAMEORIGIN'으로 설정하세요."
            }
        return None

    # 진단 모듈 3 - X-Content-Type-Options
    def _check_x_content_type_options(self, headers):
        if "X-Content-Type-Options" not in headers:
            return {
                "check_name": "Missing Security Header: X-Content-Type-Options",
                "category": self.category_2025,
                "external_result": "Header Not Found",
                "internal_result": "",
                "status": "Vulnerable",
                "risk_level": "Low",
                "evidence": "X-Content-Type-Options header is missing. MIME Sniffing attack possible.",
                "recommendation": "X-Content-Type-Options 헤더를 'nosniff'로 설정하세요."
            }
        return None

    # 진단 모듈 4 - HSTS
    def _check_hsts(self, headers):
        hsts = headers.get("Strict-Transport-Security")
        if not hsts:
            return {
                "check_name": "Missing Security Header: Strict-Transport-Security",
                "category": self.category_2025,
                "external_result": "Header Not Found",
                "internal_result": "",
                "status": "Vulnerable",
                "risk_level": "Low",
                "evidence": "Strict-Transport-Security header is missing. HTTPS connection is not enforced.",
                "recommendation": "Strict-Transport-Security 헤더를 설정하여 브라우저가 항상 HTTPS로 접속하도록 강제하세요."
            }
        return None

    # 진단 모듈 5 - Content-Security-Policy (CSP)
    def _check_csp(self, headers):
        csp = headers.get("Content-Security-Policy")
        if not csp:
            return {
                "check_name": "Missing Security Header: Content-Security-Policy",
                "category": self.category_2025,
                "external_result": "Header Not Found",
                "internal_result": "",
                "status": "Vulnerable",
                "risk_level": "High",
                "evidence": "Content-Security-Policy header is missing. Risk of XSS and data injection attacks.",
                "recommendation": "적절한 Content-Security-Policy를 설정하여 신뢰할 수 있는 스크립트만 실행되도록 제한하세요."
            }
        return None

# 실행부
if __name__ == "__main__":
    TARGET = "http://172.16.32.129:1018"
    
    scanner = ExternalScanner(TARGET)
    scan_data = scanner.run_scan() # 이제 이 함수가 정상 작동합니다.
    
    print(json.dumps(scan_data, indent=4, ensure_ascii=False))