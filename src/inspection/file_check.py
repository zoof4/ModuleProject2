import json
import re
import subprocess
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_DIR = BASE_DIR / "output"

EXTERNAL_INPUT_PATH = OUTPUT_DIR / "attack_detection_result.json"

RUN_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

RAW_OUTPUT_PATH = OUTPUT_DIR / f"internal_inspection_result_{RUN_TIMESTAMP}.json"
DASHBOARD_OUTPUT_PATH = OUTPUT_DIR / f"internal_dashboard_data_{RUN_TIMESTAMP}.json"

LATEST_RAW_OUTPUT_PATH = OUTPUT_DIR / "internal_inspection_result_latest.json"
LATEST_DASHBOARD_OUTPUT_PATH = OUTPUT_DIR / "internal_dashboard_data_latest.json"

DOCKER_CONTAINER_NAME = "studentWeb"

APACHE_CONFIG_PATHS = [
    "/etc/apache2/apache2.conf",
    "/etc/apache2/conf-enabled/security.conf",
    "/etc/apache2/sites-enabled/000-default.conf",
]

CATEGORY = "A02:2025-Security Misconfiguration"

CHECK_NAMES = [
    "ServerTokens",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
]

DEFAULT_RISK = {
    "ServerTokens": "Low",
    "X-Frame-Options": "Medium",
    "X-Content-Type-Options": "Low",
    "Strict-Transport-Security": "Low",
    "Content-Security-Policy": "High",
}


def make_result(
    check_name,
    external_result,
    internal_result,
    status,
    risk_level,
    evidence,
    recommendation,
):
    return {
        "check_name": check_name,
        "category": CATEGORY,
        "external_result": external_result,
        "internal_result": internal_result,
        "status": status,
        "risk_level": risk_level,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def read_text_file(path):
    try:
        result = subprocess.run(
            ["docker", "exec", DOCKER_CONTAINER_NAME, "cat", path],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            print(f"[READ FAIL] {path}")
            print(result.stderr.strip())
            return None

        print(f"[READ OK] {path} ({len(result.stdout)} chars)")
        return result.stdout

    except Exception as error:
        print(f"[READ ERROR] {path} -> {error}")
        return None


def collect_config_contents(paths):
    configs = {}

    for path in paths:
        content = read_text_file(path)
        if content is not None:
            configs[path] = content

    return configs


def remove_comment_lines(content):
    active_lines = []

    for line in content.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        if stripped.startswith("#"):
            continue

        active_lines.append(line)

    return "\n".join(active_lines)


def find_pattern(configs, pattern):
    matched = []

    for path, content in configs.items():
        active_content = remove_comment_lines(content)

        for line in active_content.splitlines():
            if re.search(pattern, line, re.IGNORECASE):
                matched.append(
                    {
                        "path": path,
                        "line": line.strip(),
                    }
                )

    return matched


def format_matched_lines(matched):
    if not matched:
        return "매칭된 활성 설정 없음"

    return "; ".join(
        [f"{item['path']} -> {item['line']}" for item in matched]
    )


def load_external_json(path=EXTERNAL_INPUT_PATH):
    if not Path(path).exists():
        print(f"[WARN] 외부 탐지 JSON 파일을 찾지 못했습니다: {path}")
        return []

    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

        print(f"[READ OK] 외부 탐지 JSON 로드 완료: {path}")

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            return [data]

        return []

    except json.JSONDecodeError:
        print(f"[ERROR] 외부 탐지 JSON 형식 오류: {path}")
        return []
    except Exception as error:
        print(f"[ERROR] 외부 탐지 JSON 로드 실패: {error}")
        return []


def normalize_check_name(check_name):
    name = str(check_name).lower().strip()

    if "servertokens" in name or name == "server" or "server token" in name:
        return "ServerTokens"

    if "x-frame-options" in name:
        return "X-Frame-Options"

    if "x-content-type-options" in name:
        return "X-Content-Type-Options"

    if "strict-transport-security" in name:
        return "Strict-Transport-Security"

    if "content-security-policy" in name:
        return "Content-Security-Policy"

    return check_name


def normalize_status(status):
    status = str(status).lower().strip()

    if status in ["vulnerable", "취약"]:
        return "vulnerable"

    if status in ["safe", "양호"]:
        return "safe"

    if status in ["review_required", "검토필요", "검토 필요"]:
        return "review_required"

    if status in ["n/a", "na", "not_applicable", "해당없음", "해당 없음"]:
        return "n/a"

    return "n/a"


def normalize_risk(risk_level):
    risk = str(risk_level).lower().strip()

    if risk == "high":
        return "High"

    if risk == "medium":
        return "Medium"

    if risk == "low":
        return "Low"

    return "Low"


def build_external_map(external_items):
    external_map = {}

    for item in external_items:
        raw_name = item.get("check_name", "")
        normalized_name = normalize_check_name(raw_name)

        if normalized_name not in CHECK_NAMES:
            continue

        external_map[normalized_name] = {
            "check_name": normalized_name,
            "category": item.get("category", CATEGORY),
            "external_result": item.get("external_result", "외부 탐지 결과 없음"),
            "internal_result": item.get("internal_result", ""),
            "status": normalize_status(item.get("status", "n/a")),
            "risk_level": normalize_risk(item.get("risk_level", DEFAULT_RISK.get(normalized_name, "Low"))),
            "evidence": item.get("evidence", "외부 근거 없음"),
            "recommendation": item.get("recommendation", ""),
        }

    return external_map


def get_external_item(external_map, check_name):
    return external_map.get(
        check_name,
        {
            "check_name": check_name,
            "category": CATEGORY,
            "external_result": "외부 탐지 결과 없음",
            "internal_result": "",
            "status": "n/a",
            "risk_level": DEFAULT_RISK.get(check_name, "Low"),
            "evidence": "외부 탐지 JSON에서 해당 항목을 찾지 못함",
            "recommendation": "",
        },
    )


def judge_final_status(check_name, external_status, internal_status, external_risk):
    external_status = normalize_status(external_status)
    internal_status = normalize_status(internal_status)

    default_risk = DEFAULT_RISK.get(check_name, "Low")
    external_risk = normalize_risk(external_risk)

    if external_status == "vulnerable" and internal_status == "vulnerable":
        return "Vulnerable", external_risk or default_risk

    if external_status == "safe" and internal_status == "safe":
        return "Safe", "Low"

    if external_status == "vulnerable" and internal_status == "safe":
        return "Review_Required", "Low"

    if external_status == "safe" and internal_status == "vulnerable":
        return "Vulnerable", default_risk

    if external_status == "vulnerable" and internal_status == "n/a":
        return "Review_Required", "Low"

    if external_status == "n/a" and internal_status == "vulnerable":
        return "Vulnerable", default_risk

    if external_status == "n/a" and internal_status == "safe":
        return "Safe", "Low"

    return "N/A", "Low"


def merge_external_internal_result(
    check_name,
    external_item,
    internal_status,
    internal_result,
    internal_evidence,
    safe_recommendation,
    vulnerable_recommendation,
    review_recommendation,
):
    final_status, final_risk = judge_final_status(
        check_name=check_name,
        external_status=external_item.get("status", "n/a"),
        internal_status=internal_status,
        external_risk=external_item.get("risk_level", DEFAULT_RISK.get(check_name, "Low")),
    )

    external_result = external_item.get("external_result", "외부 탐지 결과 없음")

    if final_status == "Safe":
        recommendation = safe_recommendation
    elif final_status == "Review_Required":
        recommendation = review_recommendation
    else:
        recommendation = vulnerable_recommendation

    evidence = (
        f"외부 근거: {external_item.get('evidence', '외부 근거 없음')} / "
        f"내부 근거: {internal_evidence}"
    )

    return make_result(
        check_name=check_name,
        external_result=external_result,
        internal_result=internal_result,
        status=final_status,
        risk_level=final_risk,
        evidence=evidence,
        recommendation=recommendation,
    )


def check_server_tokens(apache_configs, external_item):
    check_name = "ServerTokens"

    prod = find_pattern(apache_configs, r"ServerTokens\s+Prod")
    vulnerable = find_pattern(
        apache_configs,
        r"ServerTokens\s+(Full|OS|Major|Minor|Minimal)",
    )

    if prod:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "Apache 설정 파일에서 ServerTokens Prod 활성 설정이 확인됨",
            format_matched_lines(prod),
            "서버 버전 정보 노출이 제한되어 있습니다.",
            "Apache 설정에서 ServerTokens Prod를 적용해야 합니다.",
            "내부 설정은 ServerTokens Prod이나 외부 응답에서 상세 버전이 노출된다면 프록시, 로드밸런서, 별도 웹서버 계층의 Server 헤더를 확인해야 합니다.",
        )

    if vulnerable:
        return merge_external_internal_result(
            check_name,
            external_item,
            "vulnerable",
            "Apache 설정 파일에서 ServerTokens가 상세 정보 노출 수준으로 설정되어 있음",
            format_matched_lines(vulnerable),
            "ServerTokens 설정이 정상으로 판단됩니다.",
            "Apache 설정에서 ServerTokens Prod를 적용해야 합니다.",
            "외부 탐지 결과와 내부 설정이 일치하지 않으므로 실제 응답 서버와 내부 점검 대상 서버가 같은지 확인해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "vulnerable",
        "Apache 설정 파일에서 ServerTokens Prod 활성 설정을 찾지 못함",
        "ServerTokens 활성 설정 없음",
        "ServerTokens 설정이 정상으로 판단됩니다.",
        "Apache 보안 설정 파일에 ServerTokens Prod를 명시해야 합니다.",
        "외부 탐지 결과와 내부 설정 확인 결과가 불일치하므로 Apache 보안 설정 파일 포함 여부를 점검해야 합니다.",
    )


def check_x_frame_options(apache_configs, external_item):
    check_name = "X-Frame-Options"

    matched = find_pattern(apache_configs, r"X-Frame-Options")

    if matched:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "Apache 설정 파일에서 X-Frame-Options 활성 설정이 확인됨",
            format_matched_lines(matched),
            "현재 클릭재킹 방어 헤더가 설정되어 있습니다. DENY 또는 SAMEORIGIN 값이 적절한지 확인하는 것이 좋습니다.",
            'Apache 설정에 Header always set X-Frame-Options "SAMEORIGIN" 또는 "DENY"를 추가해야 합니다.',
            "내부 설정에는 X-Frame-Options가 있으나 외부 응답에서 누락되었다면 VirtualHost 적용 여부와 프록시 또는 캐시 환경에서 헤더 손실 여부를 점검해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "vulnerable",
        "Apache 설정 파일에서 X-Frame-Options 활성 설정을 찾지 못함",
        "X-Frame-Options 활성 설정 없음",
        "현재 X-Frame-Options 설정이 정상으로 판단됩니다.",
        'Apache 설정에 Header always set X-Frame-Options "SAMEORIGIN" 또는 "DENY"를 추가해야 합니다.',
        "외부 탐지 결과와 내부 설정이 일치하지 않으므로 Apache 설정 적용 범위를 재검토해야 합니다.",
    )


def check_x_content_type_options(apache_configs, external_item):
    check_name = "X-Content-Type-Options"

    matched = find_pattern(apache_configs, r"X-Content-Type-Options")

    if matched:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "Apache 설정 파일에서 X-Content-Type-Options 활성 설정이 확인됨",
            format_matched_lines(matched),
            "nosniff 설정이 적용되어 MIME 타입 스니핑 위험이 낮습니다.",
            'Apache 설정에 Header always set X-Content-Type-Options "nosniff"를 추가해야 합니다.',
            "내부 설정에는 X-Content-Type-Options가 있으나 외부 응답에서 누락되었다면 VirtualHost 또는 프록시 헤더 전달 설정을 확인해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "vulnerable",
        "Apache 설정 파일에서 X-Content-Type-Options 활성 설정을 찾지 못함",
        "X-Content-Type-Options 활성 설정 없음",
        "현재 X-Content-Type-Options 설정이 정상으로 판단됩니다.",
        'Apache 설정에 Header always set X-Content-Type-Options "nosniff"를 추가해야 합니다.',
        "외부 탐지 결과와 내부 설정이 일치하지 않으므로 Apache 설정 적용 범위를 재검토해야 합니다.",
    )


def check_hsts(apache_configs, external_item):
    check_name = "Strict-Transport-Security"

    matched = find_pattern(apache_configs, r"Strict-Transport-Security")

    if matched:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "Apache 설정 파일에서 HSTS 활성 설정이 확인됨",
            format_matched_lines(matched),
            "현재 HSTS 설정이 존재합니다. max-age 값과 includeSubDomains 적용 여부를 추가 확인하는 것이 좋습니다.",
            'HTTPS 환경에서 Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains" 설정을 추가해야 합니다.',
            "내부 설정에는 HSTS가 있으나 외부 응답에서 누락되었다면 HTTPS VirtualHost 적용 여부와 프록시 헤더 전달 여부를 확인해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "vulnerable",
        "Apache 설정 파일에서 HSTS 활성 설정을 찾지 못함",
        "Strict-Transport-Security 활성 설정 없음",
        "현재 HSTS 설정이 정상으로 판단됩니다.",
        'HTTPS 환경에서 Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains" 설정을 추가해야 합니다.',
        "외부 탐지 결과와 내부 설정이 일치하지 않으므로 HTTPS 적용 경로와 VirtualHost 설정을 재검토해야 합니다.",
    )


def check_csp(apache_configs, external_item):
    check_name = "Content-Security-Policy"

    matched = find_pattern(apache_configs, r"Content-Security-Policy")

    if matched:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "Apache 설정 파일에서 CSP 활성 설정이 확인됨",
            format_matched_lines(matched),
            "현재 CSP 설정이 존재합니다. unsafe-inline, unsafe-eval 사용 여부를 추가 검토하는 것이 좋습니다.",
            'Apache 설정에 Header always set Content-Security-Policy "default-src \'self\';" 설정을 추가해야 합니다.',
            "내부 설정에는 CSP가 있으나 외부 응답에서 누락되었다면 VirtualHost 적용 여부, 프록시, CDN, 캐시 계층의 헤더 전달 설정을 확인해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "vulnerable",
        "Apache 설정 파일에서 CSP 활성 설정을 찾지 못함",
        "Content-Security-Policy 활성 설정 없음",
        "현재 CSP 설정이 정상으로 판단됩니다.",
        'Apache 설정에 Header always set Content-Security-Policy "default-src \'self\';" 설정을 추가해야 합니다.',
        "외부에서는 취약으로 탐지되었으나 내부 설정 확인이 불완전할 수 있으므로 Apache Include 설정과 VirtualHost 파일을 추가 확인해야 합니다.",
    )


def run_internal_inspection(external_json_path=EXTERNAL_INPUT_PATH):
    external_items = load_external_json(external_json_path)
    external_map = build_external_map(external_items)

    apache_configs = collect_config_contents(APACHE_CONFIG_PATHS)

    results = [
        check_server_tokens(
            apache_configs,
            get_external_item(external_map, "ServerTokens"),
        ),
        check_x_frame_options(
            apache_configs,
            get_external_item(external_map, "X-Frame-Options"),
        ),
        check_x_content_type_options(
            apache_configs,
            get_external_item(external_map, "X-Content-Type-Options"),
        ),
        check_hsts(
            apache_configs,
            get_external_item(external_map, "Strict-Transport-Security"),
        ),
        check_csp(
            apache_configs,
            get_external_item(external_map, "Content-Security-Policy"),
        ),
    ]

    save_json(results, RAW_OUTPUT_PATH)
    save_json(results, LATEST_RAW_OUTPUT_PATH)

    dashboard_data = build_dashboard_data(results)

    save_json(dashboard_data, DASHBOARD_OUTPUT_PATH)
    save_json(dashboard_data, LATEST_DASHBOARD_OUTPUT_PATH)

    return results, dashboard_data


def get_dashboard_data(external_json_path=EXTERNAL_INPUT_PATH):
    _, dashboard_data = run_internal_inspection(external_json_path)
    return dashboard_data


def build_dashboard_data(results):
    summary = {
        "total": len(results),

        "vulnerable": {
            "count": 0,
            "items": []
        },
        "safe": {
            "count": 0,
            "items": []
        },
        "review_required": {
            "count": 0,
            "items": []
        },
        "n/a": {
            "count": 0,
            "items": []
        },

        "high": {
            "count": 0,
            "items": []
        },
        "medium": {
            "count": 0,
            "items": []
        },
        "low": {
            "count": 0,
            "items": []
        },
    }

    for result in results:
        check_name = result.get("check_name", "")
        status = str(result.get("status", "N/A")).lower()
        risk = str(result.get("risk_level", "Low")).lower()

        if status in summary:
            summary[status]["count"] += 1
            summary[status]["items"].append(check_name)

        if risk in summary:
            summary[risk]["count"] += 1
            summary[risk]["items"].append(check_name)

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "module": "internal_file_inspection",
        "container": DOCKER_CONTAINER_NAME,
        "summary": summary,
    }


def save_json(data, path):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)


def print_path_info():
    print(f"[BASE_DIR] {BASE_DIR}")
    print(f"[OUTPUT_DIR] {OUTPUT_DIR}")
    print(f"[EXTERNAL_INPUT_PATH] {EXTERNAL_INPUT_PATH}")
    print(f"[DOCKER_CONTAINER_NAME] {DOCKER_CONTAINER_NAME}")
    print()


def print_results(results):
    for result in results:
        print(
            f"[{result['status'].upper()}] "
            f"{result['check_name']} "
            f"({result['risk_level']})"
        )
        print(f"외부 결과: {result['external_result']}")
        print(f"내부 결과: {result['internal_result']}")
        print(f"근거: {result['evidence']}")
        print(f"대응: {result['recommendation']}")
        print()


if __name__ == "__main__":
    print_path_info()

    inspection_results, dashboard_payload = run_internal_inspection()

    print_results(inspection_results)

    print("[DASHBOARD SUMMARY]")
    print(json.dumps(dashboard_payload["summary"], indent=2, ensure_ascii=False))