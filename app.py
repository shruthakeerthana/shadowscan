from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import random
import time
import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

app = Flask(__name__)
CORS(app)

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
]

def get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

def smart_request(url):
    time.sleep(random.uniform(0.3, 0.8))
    try:
        response = requests.get(url, headers=get_headers(), timeout=5)
        return response
    except:
        return None

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    endpoints = [
        "/users", "/users/v1", "/users/v1/admin",
        "/users/v1/_debug", "/users/v1/massassignment",
        "/books", "/books/v1",
        "/login", "/users/v1/login",
        "/admin", "/config", "/secret",
        "/debug", "/internal", "/api",
        "/api/v1", "/api/v2", "/api/users",
        "/api/admin", "/api/login", "/api/register",
        "/health", "/status", "/metrics",
        "/swagger.json", "/openapi.json",
        "/api-docs", "/api/docs",
        "/v1", "/v2", "/createdb"
    ]

    found_endpoints = []
    findings = []
    vulnerabilities = []
    api_map = {}

    # SWAGGER DETECTION
    for path in ["/swagger.json", "/openapi.json", "/api-docs"]:
        response = smart_request(target + path)
        if response and response.status_code == 200:
            findings.append(f"SWAGGER RISK: {path} -> API documentation publicly accessible")
            vulnerabilities.append({
                "severity": "HIGH",
                "endpoint": path,
                "type": "INFO DISCLOSURE",
                "description": "API documentation publicly accessible"
            })
            try:
                spec = response.json()
                if "paths" in spec:
                    for ep in spec["paths"].keys():
                        if ep not in endpoints:
                            endpoints.append(ep)
            except:
                pass

    # ENDPOINT DISCOVERY
    for endpoint in endpoints:
        response = smart_request(target + endpoint)
        if response is None:
            continue
        if response.status_code == 200:
            found_endpoints.append(endpoint)
            parts = endpoint.strip("/").split("/")
            current = api_map
            for part in parts:
                if part not in current:
                    current[part] = {}
                current = current[part]

    # AUTH TEST
    sensitive = ["/admin", "/users/v1/admin", "/users/v1/_debug", "/config", "/debug", "/secret"]
    for endpoint in sensitive:
        response = smart_request(target + endpoint)
        if response and response.status_code == 200:
            findings.append(f"AUTH RISK: {endpoint} -> accessible with no authentication")
            vulnerabilities.append({
                "severity": "CRITICAL",
                "endpoint": endpoint,
                "type": "AUTH RISK",
                "description": "Accessible without authentication"
            })

    # BOLA TEST
    for endpoint in found_endpoints:
        for i in range(1, 3):
            test_url = target + endpoint + "/" + str(i)
            response = smart_request(test_url)
            if response and response.status_code == 200:
                findings.append(f"BOLA RISK: {test_url} -> accessible without auth")
                vulnerabilities.append({
                    "severity": "CRITICAL",
                    "endpoint": endpoint + "/" + str(i),
                    "type": "BOLA",
                    "description": "Object accessible without authorization"
                })

    # RATE LIMIT TEST
    if found_endpoints:
        test_ep = found_endpoints[0]
        responses = []
        for i in range(8):
            r = requests.get(target + test_ep, headers=get_headers(), timeout=5)
            responses.append(r.status_code)
        if all(r == 200 for r in responses):
            findings.append(f"RATE LIMIT RISK: {test_ep} -> no rate limiting detected")
            vulnerabilities.append({
                "severity": "HIGH",
                "endpoint": test_ep,
                "type": "RATE LIMIT",
                "description": "No rate limiting detected"
            })

    # DATA EXPOSURE TEST
    sensitive_fields = ["password", "token", "secret", "credit_card", "api_key"]
    for endpoint in found_endpoints:
        response = smart_request(target + endpoint)
        if response and response.status_code == 200:
            body = response.text.lower()
            for field in sensitive_fields:
                if field in body:
                    findings.append(f"DATA RISK: {endpoint} -> exposes '{field}' in response")
                    vulnerabilities.append({
                        "severity": "CRITICAL",
                        "endpoint": endpoint,
                        "type": "DATA EXPOSURE",
                        "description": f"Exposes '{field}' in response"
                    })

    # AI REPORT
    findings_text = "\n".join(findings) if findings else "No vulnerabilities found."
    scan_summary = f"Target: {target}\nEndpoints found: {', '.join(found_endpoints)}\nFindings:\n{findings_text}"

    chat_completion = client.chat.completions.create(
        messages=[{"role": "user", "content": f"You are a cybersecurity expert. Write a plain English security report with risk levels and fixes:\n{scan_summary}"}],
        model="llama-3.3-70b-versatile",
    )
    ai_report = chat_completion.choices[0].message.content

    return jsonify({
        "target": target,
        "endpoints_found": len(found_endpoints),
        "vulnerabilities_count": len(vulnerabilities),
        "risk_score": min(len(vulnerabilities) * 15, 100),
        "found_endpoints": found_endpoints,
        "vulnerabilities": vulnerabilities,
        "api_map": api_map,
        "ai_report": ai_report
    })

if __name__ == "__main__":
    app.run(debug=True, port=8000)
```

Paste this, save, then run:
```
git add .
git commit -m "Fix API key"
git push -u origin main