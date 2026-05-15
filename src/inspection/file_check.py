import json
import re
import subprocess
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_DIR = BASE_DIR / "output"

EXTERNAL_INPUT_PATH = OUTPUT_DIR / "attack_detection_result.json"
RAW_OUTPUT_PATH = OUTPUT_DIR / "internal_inspection_result.json"
DASHBOARD_OUTPUT_PATH = OUTPUT_DIR / "internal_dashboard_data.json"

DOCKER_CONTAINER_NAME = "studentWeb"

APACHE_CONFIG_PATHS = [
    "/etc/apache2/apache2.conf",
    "/etc/apache2/conf-enabled/security.conf",
    "/etc/apache2/sites-enabled/000-default.conf",
]

PHP_CONFIG_PATHS = [
    "/etc/php/7.4/apache2/php.ini",
]

CATEGORY = "OWASP A02"

DEFAULT_RISK = {
    "Content-Security-Policy": "High",
    "Strict-Transport-Security": "Medium",
    "X-Frame-Options": "Medium",
    "ServerTokens": "Medium",
    "ServerSignature": "Low",
    "X-Powered-By / expose_php": "Medium",
}

SCANNED_PATHS = []

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
    print(f"DEBUG: reading {path}")

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

            SCANNED_PATHS.append({
                "path": path,
                "type": "config_file",
                "result": "fail",
                "message": result.stderr.strip()
            })

            return None

        print(f"[READ OK] {path} ({len(result.stdout)} chars)")

        SCANNED_PATHS.append({
            "path": path,
            "type": "config_file",
            "result": "success",
            "message": f"{len(result.stdout)} chars loaded"
        })

        return result.stdout

    except Exception as error:
        print(f"[READ ERROR] {path} -> {error}")

        SCANNED_PATHS.append({
            "path": path,
            "type": "config_file",
            "result": "error",
            "message": str(error)
        })

        return None


def collect_config_contents(paths):
    configs = {}

    for path in paths:
        content = read_text_file(path)
        if content is not None:
            configs[path] = content

    return configs


def remove_comment_lines(content):
    lines = content.splitlines()
    active_lines = []

    for line in lines:
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

        if re.search(pattern, active_content, re.IGNORECASE):
            matched.append(path)

    return matched


def load_external_json(path=EXTERNAL_INPUT_PATH):
    if not Path(path).exists():
        print(f"[WARN] 외부 탐지 JSON 파일을 찾지 못했습니다: {path}")
        return []

    try:
        with open(path, "r", encoding="utf-8") as file:
            data = json.load(file)

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


def build_external_map(external_items):
    external_map = {}

    for item in external_items:
        check_name = item.get("check_name", "")
        if check_name:
            external_map[check_name] = item

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
            "risk_level": "Low",
            "evidence": "외부 탐지 JSON에서 해당 항목을 찾지 못함",
            "recommendation": "",
        },
    )


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


def judge_final_status(check_name, external_status, internal_status):
    external_status = normalize_status(external_status)
    internal_status = normalize_status(internal_status)

    default_risk = DEFAULT_RISK.get(check_name, "Medium")

    if external_status == "vulnerable" and internal_status == "vulnerable":
        return "vulnerable", default_risk

    if external_status == "safe" and internal_status == "safe":
        return "safe", "Low"

    if external_status == "vulnerable" and internal_status == "safe":
        return "review_required", "Low"

    if external_status == "safe" and internal_status == "vulnerable":
        return "vulnerable", default_risk

    if external_status == "vulnerable" and internal_status == "n/a":
        return "review_required", "Low"

    if external_status == "n/a" and internal_status == "vulnerable":
        return "vulnerable", default_risk

    if external_status == "n/a" and internal_status == "safe":
        return "safe", "Low"

    return "n/a", "Low"


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
    )

    external_result = external_item.get("external_result", "외부 탐지 결과 없음")

    if final_status == "safe":
        recommendation = safe_recommendation
    elif final_status == "review_required":
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


def check_csp(apache_configs, external_item):
    check_name = "Content-Security-Policy"
    matched = find_pattern(apache_configs, r"Content-Security-Policy")

    if matched:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "Apache 설정 파일에서 CSP 설정이 확인됨",
            f"CSP 설정 발견 파일: {matched}",
            "현재 CSP 설정이 존재합니다. unsafe-inline, unsafe-eval 사용 여부를 추가 검토하는 것이 좋습니다.",
            'Apache 설정에 Header always set Content-Security-Policy "default-src \'self\';" 설정을 추가해야 합니다.',
            "내부 설정에는 CSP가 있으나 외부 응답에서 누락되었다면 VirtualHost 적용 여부, 프록시, CDN, 캐시 계층의 헤더 전달 설정을 확인해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "vulnerable",
        "Apache 설정 파일에서 CSP 설정을 찾지 못함",
        "Content-Security-Policy 설정 없음",
        "현재 CSP 설정이 정상으로 판단됩니다.",
        'Apache 설정에 Header always set Content-Security-Policy "default-src \'self\';" 설정을 추가해야 합니다.',
        "외부에서는 취약으로 탐지되었으나 내부 설정 확인이 불완전할 수 있으므로 Apache Include 설정과 VirtualHost 파일을 추가 확인해야 합니다.",
    )


def check_hsts(apache_configs, external_item):
    check_name = "Strict-Transport-Security"
    matched = find_pattern(apache_configs, r"Strict-Transport-Security")

    if matched:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "Apache 설정 파일에서 HSTS 설정이 확인됨",
            f"HSTS 설정 발견 파일: {matched}",
            "현재 HSTS 설정이 존재합니다. max-age 값과 includeSubDomains 적용 여부를 추가 확인하는 것이 좋습니다.",
            'HTTPS 환경에서 Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains" 설정을 추가해야 합니다.',
            "내부 설정에는 HSTS가 있으나 외부 응답에서 누락되었다면 HTTPS VirtualHost 적용 여부와 프록시 헤더 전달 여부를 확인해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "vulnerable",
        "Apache 설정 파일에서 HSTS 설정을 찾지 못함",
        "Strict-Transport-Security 설정 없음",
        "현재 HSTS 설정이 정상으로 판단됩니다.",
        'HTTPS 환경에서 Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains" 설정을 추가해야 합니다.',
        "외부 탐지 결과와 내부 설정이 일치하지 않으므로 HTTPS 적용 경로와 VirtualHost 설정을 재검토해야 합니다.",
    )


def check_x_frame_options(apache_configs, external_item):
    check_name = "X-Frame-Options"
    matched = find_pattern(apache_configs, r"X-Frame-Options")

    if matched:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "Apache 설정 파일에서 X-Frame-Options 설정이 확인됨",
            f"X-Frame-Options 설정 발견 파일: {matched}",
            "현재 클릭재킹 방어 헤더가 설정되어 있습니다. SAMEORIGIN 또는 DENY 값이 적절한지 확인하는 것이 좋습니다.",
            'Apache 설정에 Header always set X-Frame-Options "SAMEORIGIN" 또는 "DENY"를 추가해야 합니다.',
            "내부 설정에는 X-Frame-Options가 있으나 외부 응답에서 누락되었다면 VirtualHost 적용 여부와 프록시 또는 캐시 환경에서 헤더 손실 여부를 점검해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "vulnerable",
        "Apache 설정 파일에서 X-Frame-Options 설정을 찾지 못함",
        "X-Frame-Options 활성 설정 없음",
        "현재 X-Frame-Options 설정이 정상으로 판단됩니다.",
        'Apache 설정에 Header always set X-Frame-Options "SAMEORIGIN" 또는 "DENY"를 추가해야 합니다.',
        "외부 탐지 결과와 내부 설정이 일치하지 않으므로 Apache 설정 적용 범위를 재검토해야 합니다.",
    )


def check_server_tokens(apache_configs, external_item):
    check_name = "ServerTokens"
    prod = find_pattern(apache_configs, r"ServerTokens\s+Prod")
    vulnerable = find_pattern(apache_configs, r"ServerTokens\s+(Full|OS|Major|Minor|Minimal)")

    if prod:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "Apache 설정 파일에서 ServerTokens Prod 설정이 확인됨",
            f"ServerTokens Prod 발견 파일: {prod}",
            "서버 버전 정보 노출이 제한되어 있습니다.",
            "Apache 설정에서 ServerTokens Prod로 변경해야 합니다.",
            "내부 설정은 ServerTokens Prod이나 외부 응답에서 상세 버전이 노출된다면 프록시, 로드밸런서, 별도 웹서버 계층의 Server 헤더를 확인해야 합니다.",
        )

    if vulnerable:
        return merge_external_internal_result(
            check_name,
            external_item,
            "vulnerable",
            "Apache 설정 파일에서 ServerTokens가 상세 정보 노출 수준으로 설정되어 있음",
            f"취약 ServerTokens 설정 발견 파일: {vulnerable}",
            "ServerTokens 설정이 정상으로 판단됩니다.",
            "Apache 설정에서 ServerTokens Prod로 변경해야 합니다.",
            "외부 탐지 결과와 내부 설정이 일치하지 않으므로 실제 응답 서버와 내부 점검 대상 서버가 같은지 확인해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "vulnerable",
        "Apache 설정 파일에서 ServerTokens Prod 설정을 찾지 못함",
        "ServerTokens Prod 설정 없음",
        "ServerTokens 설정이 정상으로 판단됩니다.",
        "Apache 보안 설정 파일에 ServerTokens Prod를 명시해야 합니다.",
        "외부 탐지 결과와 내부 설정 확인 결과가 불일치하므로 Apache 보안 설정 파일 포함 여부를 점검해야 합니다.",
    )


def check_server_signature(apache_configs, external_item):
    check_name = "ServerSignature"
    off = find_pattern(apache_configs, r"ServerSignature\s+Off")
    on = find_pattern(apache_configs, r"ServerSignature\s+On")

    if off:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "Apache 설정 파일에서 ServerSignature Off 설정이 확인됨",
            f"ServerSignature Off 발견 파일: {off}",
            "에러 페이지 내 서버 서명 노출이 제한되어 있습니다.",
            "Apache 설정에서 ServerSignature Off로 변경해야 합니다.",
            "내부 설정은 ServerSignature Off이나 외부에서 서버 정보가 노출된다면 에러 페이지, 프록시, 애플리케이션 응답 헤더를 추가 점검해야 합니다.",
        )

    if on:
        return merge_external_internal_result(
            check_name,
            external_item,
            "vulnerable",
            "Apache 설정 파일에서 ServerSignature On 설정이 확인됨",
            f"ServerSignature On 발견 파일: {on}",
            "ServerSignature 설정이 정상으로 판단됩니다.",
            "Apache 설정에서 ServerSignature Off로 변경해야 합니다.",
            "외부 탐지 결과와 내부 설정이 불일치하므로 에러 페이지 서버 서명 노출 여부를 추가 확인해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "vulnerable",
        "Apache 설정 파일에서 ServerSignature Off 설정을 찾지 못함",
        "ServerSignature Off 설정 없음",
        "ServerSignature 설정이 정상으로 판단됩니다.",
        "Apache 보안 설정 파일에 ServerSignature Off를 명시해야 합니다.",
        "외부 탐지 결과와 내부 설정 확인 결과가 불일치하므로 Apache 설정 파일 포함 여부를 확인해야 합니다.",
    )


def check_php_expose_php(php_configs, external_item):
    check_name = "X-Powered-By / expose_php"
    off = find_pattern(php_configs, r"expose_php\s*=\s*Off")
    on = find_pattern(php_configs, r"expose_php\s*=\s*On")

    if off:
        return merge_external_internal_result(
            check_name,
            external_item,
            "safe",
            "PHP 설정 파일에서 expose_php Off 설정이 확인됨",
            f"expose_php Off 발견 파일: {off}",
            "PHP 버전 정보 노출이 제한되어 있습니다.",
            "php.ini에서 expose_php = Off로 변경 후 Apache를 재시작해야 합니다.",
            "내부 설정은 expose_php Off이나 외부 응답에서 X-Powered-By가 노출된다면 애플리케이션 또는 프록시에서 해당 헤더를 추가하는지 확인해야 합니다.",
        )

    if on:
        return merge_external_internal_result(
            check_name,
            external_item,
            "vulnerable",
            "PHP 설정 파일에서 expose_php On 설정이 확인됨",
            f"expose_php On 발견 파일: {on}",
            "PHP expose_php 설정이 정상으로 판단됩니다.",
            "php.ini에서 expose_php = Off로 변경 후 Apache를 재시작해야 합니다.",
            "외부 탐지 결과와 내부 설정이 불일치하므로 실제 PHP 설정 파일 경로와 Apache 연동 모듈을 확인해야 합니다.",
        )

    return merge_external_internal_result(
        check_name,
        external_item,
        "n/a",
        "PHP 설정 파일 또는 expose_php 설정을 확인하지 못함",
        "php.ini 파일 또는 expose_php 설정 확인 불가",
        "PHP 설정이 정상으로 판단됩니다.",
        "PHP 사용 여부와 php.ini 경로를 확인하고 expose_php = Off 설정을 적용해야 합니다.",
        "외부에서는 X-Powered-By 노출이 탐지되었으나 내부 PHP 설정을 확인하지 못했으므로 PHP 버전과 설정 파일 경로를 추가 점검해야 합니다.",
    )


def run_internal_inspection(external_json_path=EXTERNAL_INPUT_PATH):
    external_items = load_external_json(external_json_path)
    external_map = build_external_map(external_items)

    apache_configs = collect_config_contents(APACHE_CONFIG_PATHS)
    php_configs = collect_config_contents(PHP_CONFIG_PATHS)

    results = [
        check_csp(apache_configs, get_external_item(external_map, "Content-Security-Policy")),
        check_hsts(apache_configs, get_external_item(external_map, "Strict-Transport-Security")),
        check_x_frame_options(apache_configs, get_external_item(external_map, "X-Frame-Options")),
        check_server_tokens(apache_configs, get_external_item(external_map, "ServerTokens")),
        check_server_signature(apache_configs, get_external_item(external_map, "ServerSignature")),
        check_php_expose_php(php_configs, get_external_item(external_map, "X-Powered-By / expose_php")),
    ]

    final_output = {
    "module": "internal_file_inspection",
    "container": DOCKER_CONTAINER_NAME,
    "scanned_paths": SCANNED_PATHS,
    "results": results
    }

    save_json(final_output, RAW_OUTPUT_PATH)

    dashboard_data = build_dashboard_data(results)
    dashboard_data["scanned_paths"] = SCANNED_PATHS

    save_json(dashboard_data, DASHBOARD_OUTPUT_PATH)

    return results


def build_dashboard_data(results):
    summary = {
        "total": len(results),
        "vulnerable": 0,
        "safe": 0,
        "review_required": 0,
        "n/a": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    items = []

    for result in results:
        status = result.get("status", "n/a").lower()
        risk = result.get("risk_level", "Low").lower()

        if status in summary:
            summary[status] += 1

        if risk in summary:
            summary[risk] += 1

        items.append(
            {
                "check_name": result.get("check_name", ""),
                "status": result.get("status", ""),
                "risk_level": result.get("risk_level", ""),
                "short_message": result.get("internal_result", ""),
                "recommendation": result.get("recommendation", ""),
            }
        )

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "module": "internal_file_inspection",
        "summary": summary,
        "items": items,
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
        print(f"[{result['status'].upper()}] {result['check_name']} ({result['risk_level']})")
        print(f"외부 결과: {result['external_result']}")
        print(f"내부 결과: {result['internal_result']}")
        print(f"근거: {result['evidence']}")
        print(f"대응: {result['recommendation']}")
        print()


if __name__ == "__main__":
    print_path_info()
    inspection_results = run_internal_inspection()
    print_results(inspection_results)