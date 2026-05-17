# data_loader.py
# 실제 JSON 연동 시 load_data() 함수만 수정하면 됨

import json
import os
from dummy_data import get_dummy_data


# [수정] scan_data 파라미터 추가 - 개별 위험도/상태 원본 JSON에서 가져오기
def convert_backend_json(raw: dict, scan_data: list = None) -> dict:
    """
    백엔드 JSON 구조 → 대시보드 구조로 변환
    백엔드: {status, timestamp, check_item, category, analysis: {risk_level, recommendations[{check_name, issue, remediation}]}}
    대시보드: {scan_target, scan_time, headers: [{name, alias, status, risk, description, false_positive, recommendation}]}
    """
    analysis = raw.get("analysis", {})
    recommendations = analysis.get("recommendations", [])

    # GPT 응답에서 check_name → issue, remediation 매핑
    gpt_map = {}
    for rec in recommendations:
        name = rec.get("check_name", "")
        gpt_map[name] = {
            "issue": rec.get("issue", "-"),
            "remediation": rec.get("remediation", "-")
        }

    headers = []
    if scan_data:
        # [수정] 상태와 위험도는 원본 JSON에서 직접 가져옴 (GPT 변경 방지)
        for item in scan_data:
            name = item.get("check_name", "-")
            external = item.get("external_result", "")

            # 수정 - JSON status 값 normalize해서 사용
            status_raw = item.get("status", "n/a").lower().strip()
            if status_raw in ["vulnerable", "취약"]:
                status = "vulnerable"
            elif status_raw in ["safe", "양호"]:
                status = "safe"
            elif status_raw in ["review_required", "검토필요", "검토 필요"]:
                status = "review_required"
            else:
                status = "n/a"

            # check_name 부분 일치로 GPT 설명 매핑
            gpt_data = gpt_map.get(name, {})
            if not gpt_data:
                for key, val in gpt_map.items():
                    if key in name or name in key:
                        gpt_data = val
                        break

            headers.append({
                "name": name,
                "alias": name,
                "status": status,
                # [수정] 개별 항목 위험도를 원본 JSON에서 가져옴
                "risk": item.get("risk_level", "Low"),
                "description": gpt_data.get(
                    "issue", item.get("evidence", "-")
                ),
                "false_positive": analysis.get("false_positive", False),
                "recommendation": gpt_data.get(
                    "remediation", item.get("recommendation", "-")
                ),
            })

    return {
        "scan_target": "-",  # 백엔드 JSON에 URL 없음, app.py에서 덮어씀
        "scan_time": raw.get("timestamp", "-"),
        "headers": headers,
        "gpt_summary": analysis.get("summary", ""),
    }


def load_data(json_path: str = None) -> dict:
    """
    json_path가 주어지면 실제 JSON 파일 로드,
    없으면 더미 데이터 반환
    """
    if json_path and os.path.exists(json_path):
        with open(json_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return convert_backend_json(raw)
    return get_dummy_data()


def get_summary(data: dict) -> dict:
    """헤더 목록에서 요약 통계 계산"""
    headers = data.get("headers", [])
    total = len(headers)
    risk_count = {"High": 0, "Medium": 0, "Low": 0}
    issue_count = 0

    for h in headers:
        if h["status"] != "ok":
            issue_count += 1
            risk = h.get("risk", "Low")
            if risk in risk_count:
                risk_count[risk] += 1

    return {
        "total": total,
        "issue_count": issue_count,
        "ok_count": total - issue_count,
        "risk_count": risk_count,
        "scan_target": data.get("scan_target", "-"),
        "scan_time": data.get("scan_time", "-"),
    }