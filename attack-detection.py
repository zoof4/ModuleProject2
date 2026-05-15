import requests
import json
import os
from datetime import datetime

class ExternalScanner:
    
    #웹 서버의 HTTP 응답 헤더를 분석하여 OWASP Top 10 2025 기준 
    #보안 설정 미흡(Security Misconfiguration) 항목을 진단하는 클래스
    
    def __init__(self, target_url):
        self.target_url = target_url
        # OWASP 2025 기준 항목 정의 (A02: 보안 설정 미흡)
        self.category_2025 = "A02:2025-Security Misconfiguration"
        
        # 클래스 초기화 시 대상 서버에 접속하여 헤더 정보를 미리 수집
        try:
            # timeout을 설정하여 서버 응답이 없을 경우 무한 대기 방지
            response = requests.get(self.target_url, timeout=5)
            self.headers = response.headers
        except Exception as e:
            print(f"서버 접속 실패: {e}")
            self.headers = {}

    def run_scan(self):
        
        #내부에 정의된 모든 진단 모듈을 순차적으로 실행하고 취약점 리스트를 반환
        
        results = []
        if not self.headers:
            print("진단할 헤더 정보가 없어 스캔을 중단합니다.")
            return results

        # 진단할 함수들을 리스트 형태로 관리 (확장성 고려)
        check_functions = [
            self._check_server_banner,            # 모듈 1: 서버 버전 노출 확인
            self._check_x_frame_options,          # 모듈 2: 클릭재킹 방어 확인
            self._check_x_content_type_options,   # 모듈 3: MIME 스니핑 방어 확인
            self._check_hsts,                     # 모듈 4: HTTPS 강제 설정 확인
            self._check_csp                       # 모듈 5: 콘텐츠 실행 정책 확인
        ]
        
        # 각각의 진단 함수를 호출하여 Vulnerable(취약) 결과가 나온 항목만 수집
        for func in check_functions:
            result = func(self.headers)
            if result:
                results.append(result)
        
        return results

    # 개별 진단 모듈 (내부 함수)

    def _check_server_banner(self, headers):
        #진단 모듈 1: Server 헤더를 통한 서버 종류 및 버전 노출 확인
        server_banner = headers.get("Server")
        if server_banner:
            return {
                "check_name": "Server Banner Exposure",
                "category": self.category_2025,
                "external_result": f"Detected: {server_banner}",
                "internal_result": "",  # 동준님이 설정 파일 확인 후 채울 공간
                "status": "Vulnerable",
                "risk_level": "Low",
                "evidence": f"서버 버전 정보가 노출되고 있습니다: {server_banner}",
                "recommendation": "Apache 설정에서 ServerTokens Prod, ServerSignature Off를 적용하여 정보를 숨기세요."
            }
        return None

    def _check_x_frame_options(self, headers):
        #진단 모듈 2: 클릭재킹(Clickjacking) 공격 방어용 헤더 확인
        if "X-Frame-Options" not in headers:
            return {
                "check_name": "Missing Security Header: X-Frame-Options",
                "category": self.category_2025,
                "external_result": "Header Not Found",
                "internal_result": "",
                "status": "Vulnerable",
                "risk_level": "Medium",
                "evidence": "해당 헤더가 없으면 공격자가 웹사이트를 프레임 내에 삽입하여 클릭을 유도할 수 있습니다.",
                "recommendation": "헤더 값을 'DENY' 또는 'SAMEORIGIN'으로 설정하세요."
            }
        return None

    def _check_x_content_type_options(self, headers):
        #진단 모듈 3: 잘못된 파일 형식 실행(MIME Sniffing) 방어 확인
        if "X-Content-Type-Options" not in headers:
            return {
                "check_name": "Missing Security Header: X-Content-Type-Options",
                "category": self.category_2025,
                "external_result": "Header Not Found",
                "internal_result": "",
                "status": "Vulnerable",
                "risk_level": "Low",
                "evidence": "브라우저가 파일 형식을 잘못 추측하여 악성 스크립트를 실행할 위험이 있습니다.",
                "recommendation": "헤더 값을 'nosniff'로 설정하세요."
            }
        return None

    def _check_hsts(self, headers):
        #진단 모듈 4: HTTP 엄격 전송 보안(HSTS) 설정 확인
        hsts = headers.get("Strict-Transport-Security")
        if not hsts:
            return {
                "check_name": "Missing Security Header: Strict-Transport-Security",
                "category": self.category_2025,
                "external_result": "Header Not Found",
                "internal_result": "",
                "status": "Vulnerable",
                "risk_level": "Low",
                "evidence": "중간자 공격(MitM)을 통한 HTTP 강제 접속 전환을 막을 수 없습니다.",
                "recommendation": "HTTPS 환경에서 max-age 값을 포함한 HSTS 헤더를 설정하세요."
            }
        return None

    def _check_csp(self, headers):
        #진단 모듈 5: 콘텐츠 보안 정책(CSP) 확인 - XSS 공격 방어의 핵심
        csp = headers.get("Content-Security-Policy")
        if not csp:
            return {
                "check_name": "Missing Security Header: Content-Security-Policy",
                "category": self.category_2025,
                "external_result": "Header Not Found",
                "internal_result": "",
                "status": "Vulnerable",
                "risk_level": "High", # 가장 위험도 높음
                "evidence": "신뢰할 수 없는 스크립트 실행을 차단할 수 없어 XSS 공격에 취약합니다.",
                "recommendation": "서비스에 필요한 출처(Domain)만 허용하는 화이트리스트 기반의 CSP 정책을 수립하세요."
            }
        return None

# 메인 실행부
if __name__ == "__main__":
    # 1. 진단 대상 서버 주소 (맥북에 띄워둔 웹페이지 주소)
    TARGET = "http://172.16.32.129:1018" 
    
    # 2. 스캔 실행
    scanner = ExternalScanner(TARGET)
    scan_data = scanner.run_scan()
    
    # 3. 화면 출력
    print("--- 외부 스캔 완료 ---")
    print(json.dumps(scan_data, indent=4, ensure_ascii=False))

    # 4. [핵심] 동준님 file_check.py 연동용 파일 저장
    output_dir = "output"
    output_file = "attack_detection_result.json"
    output_path = os.path.join(output_dir, output_file)

    # output 폴더가 없으면 생성
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"\n[INFO] {output_dir} 폴더를 생성했습니다.")

    # JSON 저장 (file_check.py가 이 파일을 읽으러 옵니다)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=4, ensure_ascii=False)
    
    print(f"\n✅ [SAVE OK] 연동용 파일 저장 완료: {output_path}")