import os
import json
import argparse
import logging
import glob
import platform
import plistlib  # For parsing Info.plist files
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from tenable.io import TenableIO

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('extension_scanner.log'), logging.StreamHandler()]
)
logging.getLogger('selenium').setLevel(logging.WARNING)

# Sensitive permissions for WebExtensions
SENSITIVE_PERMISSIONS = [
    "activeTab", "alarms", "background", "bookmarks", "browsingData", "clipboardRead",
    "clipboardWrite", "contentSettings", "contextMenus", "cookies", "debugger",
    "declarativeContent", "declarativeNetRequest", "declarativeWebRequest", "desktopCapture",
    "downloads", "downloads.open", "fileSystem", "geolocation", "history", "identity",
    "idle", "management", "nativeMessaging", "notifications", "pageCapture", "power",
    "privacy", "proxy", "scripting", "search", "sessions", "storage", "system.cpu",
    "system.memory", "system.storage", "tabCapture", "tabs", "topSites", "tts",
    "ttsEngine", "unlimitedStorage", "webNavigation", "webRequest", "webRequestBlocking"
]

# High-risk permissions with weights and explanations
PERMISSION_RISK_MAP = {
    "clipboardRead": {"score": 20, "explanation": "Accesses clipboard data which might contain sensitive information."},
    "clipboardWrite": {"score": 15, "explanation": "Can modify clipboard data, potentially leading to phishing."},
    "cookies": {"score": 20, "explanation": "Access to cookies can lead to session hijacking."},
    "debugger": {"score": 25, "explanation": "Allows inspection and manipulation of internal functions."},
    "management": {"score": 25, "explanation": "Can manage or modify other extensions and settings."},
    "proxy": {"score": 30, "explanation": "Allows interception and redirection of network traffic."},
    "webRequest": {"score": 20, "explanation": "Enables monitoring of network requests, risking data leaks."},
    "webRequestBlocking": {"score": 25, "explanation": "Can block or modify network traffic."},
    "*://*/*": {"score": 30, "explanation": "Broad host permission grants access to all websites."}
}

# Suspicious JavaScript code patterns
SUSPICIOUS_PATTERNS = [
    "eval(", "new Function(", "document.write(", "innerHTML", "setTimeout(",
    "setInterval(", "XMLHttpRequest(", "fetch(", "WebSocket(", "postMessage(",
    "Worker(", "SharedWorker(", "ServiceWorker("
]

def get_extension_paths(browser):
    """Get paths to browser extension directories based on OS and browser."""
    system = platform.system()
    user_home = os.path.expanduser('~')
    paths = []

    if browser.lower() == 'chrome':
        paths = {
            'Windows': os.path.join(user_home, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'Extensions'),
            'Linux': os.path.join(user_home, '.config', 'google-chrome', 'Default', 'Extensions'),
            'Darwin': os.path.join(user_home, 'Library', 'Application Support', 'Google', 'Chrome', 'Default', 'Extensions')
        }.get(system)
    elif browser.lower() == 'edge':
        paths = {
            'Windows': os.path.join(user_home, 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions'),
            'Linux': os.path.join(user_home, '.config', 'microsoft-edge', 'Default', 'Extensions'),
            'Darwin': os.path.join(user_home, 'Library', 'Application Support', 'Microsoft Edge', 'Default', 'Extensions')
        }.get(system)
    elif browser.lower() == 'firefox':
        profile_base = {
            'Windows': os.path.join(user_home, 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles'),
            'Linux': os.path.join(user_home, '.mozilla', 'firefox'),
            'Darwin': os.path.join(user_home, 'Library', 'Application Support', 'Firefox', 'Profiles')
        }.get(system)
        profiles = glob.glob(os.path.join(profile_base, '*.default*'))
        return [os.path.join(p, 'extensions') for p in profiles if os.path.exists(os.path.join(p, 'extensions'))]
    elif browser.lower() == 'safari' and system == 'Darwin':
        paths = os.path.join(user_home, 'Library', 'Safari', 'Extensions')

    if not paths or (isinstance(paths, str) and not os.path.exists(paths)):
        logging.warning(f"Extension path not found or unsupported for {browser} on {system}")
        return []
    return [paths] if isinstance(paths, str) else paths

def find_extensions(browser):
    """Find installed browser extensions."""
    paths = get_extension_paths(browser)
    if not paths:
        return []
    extensions = []
    for path in paths:
        if os.path.exists(path):
            extensions.extend(os.path.join(path, d) for d in os.listdir(path) if os.path.isdir(os.path.join(path, d)))
    logging.info(f"Found {len(extensions)} extensions for {browser}")
    return extensions

def find_file(extension_path, filename):
    """Search for a specific file in the extension directory and subdirectories."""
    for root, _, files in os.walk(extension_path):
        if filename in files:
            return os.path.join(root, filename)
    return None

def get_webextension_info(manifest_path):
    """Extract permissions and metadata from manifest.json (WebExtensions)."""
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
            metadata = {'name': manifest.get('name', 'Unknown'), 'type': 'WebExtension'}
            permissions = manifest.get('permissions', []) + manifest.get('optional_permissions', [])
            if 'content_scripts' in manifest:
                for script in manifest['content_scripts']:
                    permissions.extend(script.get('matches', []))
        return list(set(permissions)), metadata
    except Exception as e:
        logging.error(f"Failed to parse manifest.json at {manifest_path}: {e}")
        return [], {}

def get_safari_app_extension_info(info_path):
    """Extract metadata from Info.plist for Safari App Extensions."""
    try:
        with open(info_path, 'rb') as f:
            info = plistlib.load(f)
        metadata = {
            'name': info.get('CFBundleName', 'Unknown'),
            'version': info.get('CFBundleShortVersionString', 'Unknown'),
            'type': 'Safari App Extension'
        }
        # No explicit permissions in Info.plist; capabilities inferred from code
        return [], metadata
    except Exception as e:
        logging.error(f"Failed to parse Info.plist at {info_path}: {e}")
        return [], {}

def static_analysis(extension_path, browser):
    """Perform static analysis on extensions."""
    findings = {'permissions': [], 'metadata': {}, 'permission_issues': [], 'code_pattern_issues': []}
    if browser.lower() == 'safari':
        # Check for WebExtensions first (manifest.json)
        manifest_path = find_file(extension_path, 'manifest.json')
        if manifest_path:
            permissions, metadata = get_webextension_info(manifest_path)
        else:
            # Fall back to Safari App Extensions (Info.plist)
            info_path = find_file(extension_path, 'Info.plist')
            if info_path:
                permissions, metadata = get_safari_app_extension_info(info_path)
            else:
                logging.warning(f"No manifest.json or Info.plist found in {extension_path}")
                return findings
    else:
        # Other browsers use manifest.json
        manifest_path = find_file(extension_path, 'manifest.json')
        if manifest_path:
            permissions, metadata = get_webextension_info(manifest_path)
        else:
            logging.warning(f"manifest.json not found in {extension_path}")
            return findings

    findings['permissions'] = permissions
    findings['metadata'] = metadata
    if permissions:
        perm_issues, _ = evaluate_permissions_risk(permissions)
        findings['permission_issues'] = perm_issues
    findings['code_pattern_issues'] = check_code_patterns(extension_path)
    return findings

def evaluate_permissions_risk(permissions):
    """Evaluate permissions for risk."""
    issues = []
    total_perm_score = 0
    for p in permissions:
        if p in PERMISSION_RISK_MAP:
            issue = {
                "permission": p,
                "score": PERMISSION_RISK_MAP[p]["score"],
                "explanation": PERMISSION_RISK_MAP[p]["explanation"]
            }
            issues.append(issue)
            total_perm_score += PERMISSION_RISK_MAP[p]["score"]
        elif p in SENSITIVE_PERMISSIONS:
            default_score = 10
            issue = {
                "permission": p,
                "score": default_score,
                "explanation": f"Sensitive permission '{p}' may be abused if not necessary."
            }
            issues.append(issue)
            total_perm_score += default_score
    return issues, total_perm_score

def check_code_patterns(extension_dir):
    """Scan JavaScript files for suspicious patterns."""
    issues = []
    for root, _, files in os.walk(extension_dir):
        for file in files:
            if file.endswith('.js'):
                try:
                    with open(os.path.join(root, file), 'r', errors='ignore') as f:
                        content = f.read()
                        for pattern in SUSPICIOUS_PATTERNS:
                            if pattern in content:
                                issues.append({
                                    "issue": f"Suspicious pattern '{pattern}' in {file}",
                                    "details": "May execute dynamic code or alter content.",
                                    "impact": "Potential malware or unsafe execution."
                                })
                except Exception as e:
                    logging.warning(f"Failed to scan {file}: {e}")
    return issues

def dynamic_analysis(extension_path, browser):
    """Perform dynamic analysis (not supported for Safari)."""
    findings = {}
    if browser.lower() not in ['chrome', 'edge']:
        findings['network_requests'] = f"Dynamic analysis not supported for {browser}"
        return findings

    version_dirs = [d for d in os.listdir(extension_path) if os.path.isdir(os.path.join(extension_path, d))]
    if not version_dirs:
        logging.warning(f"No version directories in {extension_path}")
        findings['network_requests'] = "No version directories found"
        return findings

    version_dir = os.path.join(extension_path, version_dirs[0])
    chrome_options = Options()
    chrome_options.add_argument(f"--load-extension={version_dir}")
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")

    driver = None
    for attempt in range(3):
        try:
            driver = webdriver.Chrome(options=chrome_options)
            driver.get("https://example.com")
            network_logs = driver.execute_script("return window.performance.getEntries();")
            findings['network_requests'] = network_logs
            break
        except Exception as e:
            logging.warning(f"Dynamic analysis attempt {attempt + 1} failed: {e}")
            if driver:
                driver.quit()
        finally:
            if driver:
                driver.quit()
    else:
        findings['network_requests'] = "Failed after 3 attempts"
    return findings

def analyze_extension(extension_path, browser):
    """Analyze an extension using static and dynamic methods."""
    findings = {'static': static_analysis(extension_path, browser), 'dynamic': dynamic_analysis(extension_path, browser)}
    return findings

def calculate_risk_score(findings):
    """Calculate risk score based on permissions, code patterns, and network activity."""
    breakdown = {}
    static = findings['static']
    dynamic = findings['dynamic']

    # Permissions risk
    _, perm_score = evaluate_permissions_risk(static['permissions'])
    breakdown['permissions'] = perm_score

    # Code pattern risk: 10 points per issue
    code_issues = len(static['code_pattern_issues'])
    code_score = code_issues * 10
    breakdown['code_patterns'] = code_score

    # Network activity risk: 5 points per request above 3
    network_score = 0
    if isinstance(dynamic.get('network_requests'), list):
        network_count = len(dynamic['network_requests'])
        network_score = max(0, (network_count - 3)) * 5
    breakdown['network'] = network_score

    total_score = breakdown['permissions'] + breakdown['code_patterns'] + breakdown['network']
    risk_score = min(total_score, 100)
    findings['score_breakdown'] = breakdown
    findings['permission_issues_detailed'] = static['permission_issues']
    return risk_score

def save_findings(extension_id, findings, browser, risk_score):
    """Save findings to a JSON file."""
    reports_dir = 'reports'
    os.makedirs(reports_dir, exist_ok=True)
    report_file = os.path.join(reports_dir, f'{browser}_report_{extension_id}.json')

    metadata = findings['static'].get('metadata', {})
    summary = {
        'extension_name': metadata.get('name', 'Unknown'),
        'type': metadata.get('type', 'Unknown'),
        'risk_score': risk_score,
        'risk_breakdown': findings.get('score_breakdown', {}),
        'overall_risk': 'Critical' if risk_score > 75 else 'High' if risk_score > 50 else 'Medium' if risk_score > 25 else 'Low',
        'risks': {
            'permissions': findings.get('permission_issues_detailed', []),
            'code_patterns': findings['static'].get('code_pattern_issues', []),
            'network_activity': (
                f"Detected {len(findings['dynamic']['network_requests'])} requests"
                if isinstance(findings['dynamic'].get('network_requests'), list)
                else findings['dynamic'].get('network_requests', 'None')
            )
        }
    }

    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump({'summary': summary, 'detailed_findings': findings}, f, indent=2)
    logging.info(f"Saved findings for {extension_id} ({browser}) with risk score {risk_score}")
    return summary

def create_summary_finding(extension_findings):
    """Create an aggregated summary of all extension findings."""
    host = platform.node()
    summary_lines = []
    overall_risk_score = 0

    for finding in extension_findings:
        ext_name = finding.get('extension_name', 'Unknown Extension')
        risk_score = finding.get('risk_score', 0)
        breakdown = finding.get('risk_breakdown', {})
        overall_risk_score = max(overall_risk_score, risk_score)
        detailed_issues = finding.get('risks', {})
        summary_lines.append(
            f"Extension Name: {ext_name}\n"
            f"  Risk Score: {risk_score}\n"
            f"  Risk Breakdown: {breakdown}\n"
            f"  Detailed Issues:\n"
            f"    Permissions Issues: {detailed_issues.get('permissions', 'None')}\n"
            f"    Code Pattern Issues: {detailed_issues.get('code_patterns', 'None')}\n"
            f"    Network Activity: {detailed_issues.get('network_activity', 'None')}\n"
        )

    overall_severity = (
        'Critical' if overall_risk_score > 75 else
        'High' if overall_risk_score > 50 else
        'Medium' if overall_risk_score > 25 else
        'Low'
    )

    description = (
        f"Aggregated Browser Extensions Security Report for host '{host}'\n"
        f"Total Extensions Scanned: {len(extension_findings)}\n\n"
        "Detailed Extension Findings:\n"
        "-----------------------------\n"
        + "\n".join(summary_lines) +
        "\n-----------------------------\n"
        f"Overall Highest Risk Score: {overall_risk_score}\n"
        f"Overall Severity: {overall_severity}\n"
    )

    aggregated_summary = {
        "host": host,
        "plugin_id": 900001,
        "plugin_name": "Aggregated Browser Extensions Security Report",
        "description": description,
        "severity": overall_severity,
        "extensions_summary": extension_findings
    }
    return aggregated_summary

def save_aggregated_summary(aggregated_summary):
    """Save the aggregated summary report locally."""
    reports_dir = 'reports'
    os.makedirs(reports_dir, exist_ok=True)
    report_file = os.path.join(reports_dir, "aggregated_extensions_report.json")
    try:
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(aggregated_summary, f, indent=2)
        logging.info(f"Saved aggregated summary to {report_file}")
    except Exception as e:
        logging.error(f"Failed to save aggregated summary: {e}")

def report_to_tenable(summary, tio):
    """Report findings to Tenable."""
    try:
        tio.vulnerabilities.import_vuln(summary)
        logging.info(f"Reported to Tenable with severity {summary['severity']}")
    except Exception as e:
        logging.error(f"Failed to report to Tenable: {e}")

def main():
    """Main function to scan extensions and report findings."""
    parser = argparse.ArgumentParser(description='Scan browser extensions and report to Tenable')
    parser.add_argument('--browser', choices=['chrome', 'edge', 'firefox', 'safari'])
    parser.add_argument('--tenable-access-key', default=os.getenv('TENABLE_ACCESS_KEY'))
    parser.add_argument('--tenable-secret-key', default=os.getenv('TENABLE_SECRET_KEY'))
    args = parser.parse_args()

    browsers = [args.browser] if args.browser else ['chrome', 'edge', 'firefox', 'safari']
    tio = None
    if args.tenable_access_key and args.tenable_secret_key:
        try:
            tio = TenableIO(access_key=args.tenable_access_key, secret_key=args.tenable_secret_key)
        except Exception as e:
            logging.error(f"Failed to initialize TenableIO: {e}")

    aggregated_findings = []

    for browser in browsers:
        logging.info(f"Scanning extensions for {browser}...")
        extensions = find_extensions(browser)
        if not extensions:
            logging.info(f"No extensions found for {browser}")
            continue

        for ext_path in extensions:
            extension_id = os.path.basename(ext_path)
            logging.info(f"Analyzing extension: {extension_id} ({browser})")
            findings = analyze_extension(ext_path, browser)
            risk_score = calculate_risk_score(findings)
            summary = save_findings(extension_id, findings, browser, risk_score)
            aggregated_findings.append(summary)

    if aggregated_findings:
        aggregated_summary = create_summary_finding(aggregated_findings)
        save_aggregated_summary(aggregated_summary)
        if tio:
            report_to_tenable(aggregated_summary, tio)
        else:
            logging.info("TenableIO not configured; summary saved locally")
    else:
        logging.info("No findings to aggregate")

if __name__ == "__main__":
    main()