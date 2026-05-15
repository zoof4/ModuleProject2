import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path
from src.gpt.response_format import get_system_prompt, format_gpt_response, save_result

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def analyze_scan_result(scan_result: dict) -> dict:
    """GPT API와 통신하여 전문적인 분석 결과를 가져옵니다."""
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.5, # 창의성과 정확성의 균형
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": get_system_prompt()},
                {"role": "user", "content": f"다음 진단 데이터를 분석하세요: {json.dumps(scan_result)}"}
            ]
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"error": f"API 호출 실패: {str(e)}"}

def run_analysis(json_path: str) -> dict:
    """[통합 함수] 파일 로드 -> AI 분석 -> 포맷팅 -> 저장"""
    # 1. 파일 로드
    path = Path(json_path)
    if not path.exists():
        return {"status": "error", "message": "파일을 찾을 수 없습니다."}
    
    with open(path, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    # 2. AI 분석 수행
    raw_ai_response = analyze_scan_result(scan_data)
    
    if "error" in raw_ai_response:
        return raw_ai_response

    # 3. 데이터 표준화 및 메타데이터 결합
    final_report = format_gpt_response(raw_ai_response, scan_data)
    
    # 4. 파일 저장
    save_result(final_report)
    
    return final_report