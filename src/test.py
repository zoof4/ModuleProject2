from src.gpt.api import run_analysis
import json

def test_system():
    input_file = "output/test_result.json"
    
    print("🚀 [시스템 시작] AI 보안 컨설턴트가 분석을 진행합니다...")
    
    report = run_analysis(input_file)
    
    # 에러 핸들링 보강
    if not report:
        print("❌ 실패: 결과가 생성되지 않았습니다 (None 반환)")
        return

    if "error" in report:
        print(f"❌ 실패: {report.get('error')}")
        return

    print("\n" + "-" * 50)
    print("📊 AI 전문 보안 분석 결과")
    print("=" * 50)
    
    # 요청하신 구조에 맞게 출력부 수정
    print(f"🚩 위험도: {report.get('risk_level')}")
    print(f"📝 요약: {report.get('summary')}")
    print(f"🔢 권고 수: {report.get('recommendation_count')}")
    print("-" * 50)
    
    for r in report.get('recommendations', []):
        print(f"🔎 항목명: {r.get('check_name')}")
        print(f"💡 위험 상세: {r.get('issue')}")
        print(f"🛠️ 조치 가이드: \n{r.get('remediation')}")
    print("-" * 50 + "\n")

if __name__ == "__main__":
    test_system()
