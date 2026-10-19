#!/usr/bin/env python3
import io
import json
import subprocess
from pathlib import Path


BASE_URL = "http://127.0.0.1:5000"
ADMIN_PASSWORD = "Admin-Demo-Password-2026!"
output = io.StringIO()


def emit(text=""):
    print(text)
    output.write(text + "\n")


def run_curl(arguments, include_headers=False):
    command = ["curl", "--silent", "--show-error", "--max-time", "10"]
    if include_headers:
        command.append("--include")
    command.extend(arguments)
    emit("COMMAND: " + " ".join(command))
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.stderr:
        emit(result.stderr.strip())
    emit(result.stdout.strip())
    emit()
    return result


emit("== 1. Public health endpoint ==")
run_curl([BASE_URL + "/health"])

emit("== 2. Protected endpoint without a token ==")
run_curl([BASE_URL + "/api/data"], include_headers=True)

emit("== 3. Login with valid credentials ==")
login_arguments = [
    "-X",
    "POST",
    "-H",
    "Content-Type: application/json",
    "-d",
    json.dumps({"username": "admin", "password": ADMIN_PASSWORD}),
    BASE_URL + "/api/auth/login",
]
login_result = run_curl(login_arguments)
login_body = json.loads(login_result.stdout)
token = login_body["access_token"]
emit("JWT prefix: " + token[:32] + "...")
emit()

emit("== 4. Protected data with a valid JWT ==")
run_curl(
    ["-H", "Authorization: Bearer " + token, BASE_URL + "/api/data"],
    include_headers=True,
)

emit("== 5. SQL injection login attempt ==")
run_curl(
    [
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "-d",
        json.dumps({"username": "admin' OR '1'='1' --", "password": "anything"}),
        BASE_URL + "/api/auth/login",
    ]
)

emit("== 6. XSS payload submission ==")
xss_payload = '<script>alert("xss")</script><img src=x onerror=alert(1)>'
run_curl(
    [
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "-H",
        "Authorization: Bearer " + token,
        "-d",
        json.dumps({"title": "XSS check", "body": xss_payload}),
        BASE_URL + "/api/posts",
    ]
)

emit("== 7. XSS payload after output encoding ==")
data_result = run_curl(
    ["-H", "Authorization: Bearer " + token, BASE_URL + "/api/data"]
)

if "<script>" in data_result.stdout or "&lt;script&gt;" not in data_result.stdout:
    raise SystemExit("XSS output-encoding check failed")

Path("reports/api-smoke.txt").write_text(output.getvalue(), encoding="utf-8")
emit("API smoke test completed successfully.")
