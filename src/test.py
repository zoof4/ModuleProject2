from src.gpt.api import run_analysis
import json

def test_system():
    # 실제 진단 도구가 생성했을 법한 파일 경로
    input_file = "output/test_result.json"
    
    print("🚀 [시스템 시작] AI 보안 컨설턴트가 분석을 진행합니다...")
    
    # 분석 실행
    report = run_analysis(input_file)
    
    if report.get("status") == "success":
        data = report["analysis"]
        print("\n" + "★" * 50)
        print(f"📊 항목명: {report['check_item']} ({report['category']})")
        print(f"🚩 위험도: {data['risk_level']}")
        print(f"📝 요약: {data['summary']}")
        print("-" * 50)
        
        for r in data['recommendations']:
            print(f"💡 위험 상세: {r['issue']}")
            print(f"🛠️ 조치 가이드: \n{r['remediation']}")
        print("★" * 50 + "\n")
    else:
        print(f"❌ 실패: {report.get('message')}")

if __name__ == "__main__":
    test_system()