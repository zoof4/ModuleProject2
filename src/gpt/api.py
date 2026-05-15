import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path
from src.gpt.response_format import get_system_prompt, format_gpt_response, save_result

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def analyze_scan_result(scan_result: dict) -> dict:
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": get_system_prompt()},
                {"role": "user", "content": f"데이터 분석: {json.dumps(scan_result)}"}
            ]
        )
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        return {"error": str(e)}

def run_analysis(json_path: str) -> dict:
    path = Path(json_path)
    if not path.exists():
        return {"error": "파일을 찾을 수 없습니다."}
    
    with open(path, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    raw_ai_response = analyze_scan_result(scan_data)
    
    if "error" in raw_ai_response:
        return raw_ai_response

    final_report = format_gpt_response(raw_ai_response, scan_data)
    
    save_result(final_report, scan_data.get("check_name", "Result"))
    
    return final_report
