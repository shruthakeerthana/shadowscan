import requests
import random
import time
import json
from groq import Groq
import os
from dotenv import load_dotenv
load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Rotating User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15"
]

def get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

def smart_request(url):
    time.sleep(random.uniform(0.5, 1.5))
    session = requests.Session()
    try:
        response = session.get(url, headers=get_headers(), timeout=5)
        return response
    except:
        return None
    
def crawl_js_files(target):
    print("--- JS File Crawling ---\n")
    discovered = []
    try:
        response = requests.get(target, headers=get_headers(), timeout=5)
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, "html.parser")
        scripts = soup.find_all("script", src=True)
        
        if not scripts:
            print("No JS files found on homepage.")
            return discovered
        
        for script in scripts:
            src = script["src"]
            if not src.startswith("http"):
                src = target + src
            print("Found JS file: " + src)
            
            try:
                js_response = requests.get(src, headers=get_headers(), timeout=5)
                js_content = js_response.text
                
                import re
                api_patterns = re.findall(r'["\'](/api/[^"\']+|/v\d+/[^"\']+|/users/[^"\']+|/auth/[^"\']+)["\']', js_content)
                
                for endpoint in api_patterns:
                    if endpoint not in discovered:
                        discovered.append(endpoint)
                        print("  Endpoint found in JS: " + endpoint)
            except:
                pass
    except:
        print("Could not crawl JS files.")
    
    return discovered

target = input("Enter target URL (e.g. http://localhost:5000): ").strip()

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
    "/v1", "/v2", "/v3",
    "/createdb"
]

print("\nScanning " + target + "...\n")

js_endpoints = crawl_js_files(target)
for ep in js_endpoints:
    if ep not in endpoints:
        endpoints.append(ep)
        print("Added from JS: " + ep)

found_endpoints = []
findings = []
api_map = {}

# OPENAPI/SWAGGER DETECTION
print("--- Checking for API Documentation ---\n")

swagger_paths = ["/swagger.json", "/openapi.json", "/api-docs", "/api/docs", "/swagger/v1/swagger.json"]
for path in swagger_paths:
    response = smart_request(target + path)
    if response and response.status_code == 200:
        print("SWAGGER FOUND: " + path + " -> API documentation exposed!")
        findings.append("SWAGGER RISK: " + path + " -> API documentation publicly accessible")
        try:
            spec = response.json()
            if "paths" in spec:
                print("Extracting endpoints from API spec...")
                for ep in spec["paths"].keys():
                    if ep not in endpoints:
                        endpoints.append(ep)
                        print("  Added from spec: " + ep)
        except:
            pass

# ENDPOINT DISCOVERY
print("\n--- Endpoint Discovery ---\n")

for endpoint in endpoints:
    response = smart_request(target + endpoint)
    if response is None:
        continue
    if response.status_code == 200:
        print("FOUND: " + endpoint + " -> 200")
        found_endpoints.append(endpoint)
        # Build API map
        parts = endpoint.strip("/").split("/")
        current = api_map
        for part in parts:
            if part not in current:
                current[part] = {}
            current = current[part]
    elif response.status_code not in [404, 400]:
        print("INTERESTING: " + endpoint + " -> " + str(response.status_code))

# BOLA TEST
print("\n--- BOLA Test ---\n")

for endpoint in found_endpoints:
    for i in range(1, 4):
        test_url = target + endpoint + "/" + str(i)
        response = smart_request(test_url)
        if response and response.status_code == 200:
            msg = "BOLA RISK: " + test_url + " -> accessible without auth"
            print(msg)
            findings.append(msg)

# AUTH TEST
print("\n--- Authentication Test ---\n")

sensitive = ["/admin", "/dashboard", "/config", "/internal", "/debug", "/secret", "/users/v1/admin", "/users/v1/_debug"]

for endpoint in sensitive:
    response = smart_request(target + endpoint)
    if response is None:
        continue
    if response.status_code == 200:
        msg = "AUTH RISK: " + endpoint + " -> accessible with no authentication"
        print(msg)
        findings.append(msg)
    elif response.status_code == 403:
        print("PROTECTED: " + endpoint + " -> blocked (good)")
    elif response.status_code == 401:
        print("PROTECTED: " + endpoint + " -> requires login (good)")

# MASS ASSIGNMENT TEST
print("\n--- Mass Assignment Test ---\n")

for endpoint in found_endpoints:
    if "login" in endpoint or "register" in endpoint or "users" in endpoint:
        test_payload = {
            "username": "testuser",
            "password": "testpass",
            "admin": True,
            "role": "admin",
            "is_admin": True
        }
        try:
            response = requests.post(
                target + endpoint,
                json=test_payload,
                headers=get_headers(),
                timeout=5
            )
            if response.status_code in [200, 201]:
                msg = "MASS ASSIGNMENT RISK: " + endpoint + " -> accepts admin/role fields in request"
                print(msg)
                findings.append(msg)
            else:
                print("SAFE: " + endpoint + " -> rejected extra fields (" + str(response.status_code) + ")")
        except:
            pass

# RATE LIMIT TEST
print("\n--- Rate Limit Test ---\n")

if found_endpoints:
    test_endpoint = found_endpoints[0]
    print("Testing rate limiting on " + test_endpoint + "...")
    responses = []
    for i in range(10):
        response = requests.get(target + test_endpoint, headers=get_headers(), timeout=5)
        responses.append(response.status_code)
    
    if all(r == 200 for r in responses):
        msg = "RATE LIMIT RISK: " + test_endpoint + " -> no rate limiting detected (10 rapid requests all succeeded)"
        print(msg)
        findings.append(msg)
    else:
        print("PROTECTED: Rate limiting detected")

# DATA EXPOSURE TEST
print("\n--- Excessive Data Exposure Test ---\n")

sensitive_fields = ["password", "token", "secret", "credit_card", "ssn", "private_key", "api_key"]

for endpoint in found_endpoints:
    response = smart_request(target + endpoint)
    if response and response.status_code == 200:
        body = response.text.lower()
        for field in sensitive_fields:
            if field in body:
                msg = "DATA RISK: " + endpoint + " -> exposes '" + field + "' in response"
                print(msg)
                findings.append(msg)

# API MAP VISUALIZATION
print("\n--- API Map ---\n")

def print_tree(node, prefix="", path=""):
    items = list(node.keys())
    for i, key in enumerate(items):
        is_last = i == len(items) - 1
        current_path = path + "/" + key
        risk = ""
        if current_path in [f.split(" -> ")[0].replace("AUTH RISK: ", "").replace("DATA RISK: ", "") for f in findings]:
            risk = " [CRITICAL]"
        elif current_path in found_endpoints:
            risk = " [LOW]"
        connector = "└── " if is_last else "├── "
        print(prefix + connector + "/" + key + risk)
        extension = "    " if is_last else "│   "
        print_tree(node[key], prefix + extension, current_path)

print(target)
print_tree(api_map)

# AI REPORT
print("\n--- AI Report ---\n")

if findings:
    findings_text = "\n".join(findings)
else:
    findings_text = "No critical vulnerabilities found."

scan_summary = f"""
Target scanned: {target}
Endpoints discovered: {', '.join(found_endpoints) if found_endpoints else 'None'}
Vulnerabilities found:
{findings_text}
"""

chat_completion = client.chat.completions.create(
    messages=[
        {
            "role": "user",
            "content": f"You are a cybersecurity expert. Analyze these API scan results and write a plain English security report with risk levels and how to fix each issue:\n{scan_summary}"
        }
    ],
    model="llama-3.3-70b-versatile",
)

report = chat_completion.choices[0].message.content
print(report)

# SAVE REPORT
with open("shadowscan_report.txt", "w") as f:
    f.write("ShadowScan Security Report\n")
    f.write("==========================\n")
    f.write("Target: " + target + "\n\n")
    f.write("Raw Findings:\n")
    f.write(findings_text + "\n\n")
    f.write("AI Analysis:\n")
    f.write(report)

print("\nReport saved to shadowscan_report.txt")
print("\nScan complete.")