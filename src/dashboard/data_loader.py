# data_loader.py
# 실제 JSON 연동 시 load_data() 함수만 수정하면 됨

import json
import os
from dummy_data import get_dummy_data

def load_data(json_path: str = None) -> dict:
    """
    json_path가 주어지면 실제 JSON 파일 로드,
    없으면 더미 데이터 반환
    """
    if json_path and os.path.exists(json_path):
        with open(json_path, "r", encoding="utf-8") as f:
            return json.load(f)
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
