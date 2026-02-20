#!/usr/bin/env python3
"""
API key: https://console.anthropic.com/ → Settings → API Keys. Set env ANTHROPIC_API_KEY.
Usage:  from anthropic_files import upload, download, test_jwt_with_proxy
        python anthropic_files.py  → runs test_jwt_with_proxy() with hardcoded JWT + google.com
"""
import os, sys
try: import requests
except ImportError: print("pip install requests", file=sys.stderr); sys.exit(1)

H = lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01", "anthropic-beta": "files-api-2025-04-14"}

def upload(path: str, api_key: str | None = None) -> dict:
    k = api_key or os.environ.get("ANTHROPIC_API_KEY") or (_ for _ in ()).throw(ValueError("ANTHROPIC_API_KEY not set"))
    with open(path, "rb") as f: r = requests.post("https://api.anthropic.com/v1/files", headers=H(k), files={"file": (os.path.basename(path), f)}, params={"beta": "true"})
    r.raise_for_status()
    return r.json()

def download(file_id: str, save_path: str | None = None, api_key: str | None = None) -> bytes:
    k = api_key or os.environ.get("ANTHROPIC_API_KEY") or (_ for _ in ()).throw(ValueError("ANTHROPIC_API_KEY not set"))
    r = requests.get(f"https://api.anthropic.com/v1/files/{file_id}/content", headers=H(k), params={"beta": "true"})
    r.raise_for_status()
    data = r.content
    if save_path: open(save_path, "wb").write(data)
    return data



# Hardcoded for auto-run from main
JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6Iks3dlRfYUVsdXIySGdsYVJ0QWJ0UThDWDU4dFFqODZIRjJlX1VsSzZkNEEifQ.eyJpc3MiOiJhbnRocm9waWMtZWdyZXNzLWNvbnRyb2wiLCJvcmdhbml6YXRpb25fdXVpZCI6ImE1YTZkNDI0LTEyMDUtNGVkNi1iODcxLWM3MjI5MDUxN2QyOSIsImlhdCI6MTc3MTYzMDgzMywiZXhwIjoxNzcxNjQ1MjMzLCJhbGxvd2VkX2hvc3RzIjoiKi5haSwqLmNvbSwqLmlvLCoubmUsKi5uZXQsYXBpLmFudGhyb3BpYy5jb20sYXJjaGl2ZS51YnVudHUuY29tLGNyYXRlcy5pbyxmaWxlcy5weXRob25ob3N0ZWQub3JnLGdpdGh1Yi5jb20saW5kZXguY3JhdGVzLmlvLG5wbWpzLmNvbSxucG1qcy5vcmcscHlwaS5vcmcscHl0aG9uaG9zdGVkLm9yZyxyZWdpc3RyeS5ucG1qcy5vcmcscmVnaXN0cnkueWFybnBrZy5jb20sc2VjdXJpdHkudWJ1bnR1LmNvbSxzdGF0aWMuY3JhdGVzLmlvLHd3dy5ucG1qcy5jb20sd3d3Lm5wbWpzLm9yZyx5YXJucGtnLmNvbSIsImlzX2hpcGFhX3JlZ3VsYXRlZCI6ImZhbHNlIiwiaXNfYW50X2hpcGkiOiJmYWxzZSIsInVzZV9lZ3Jlc3NfZ2F0ZXdheSI6InRydWUiLCJjb250YWluZXJfaWQiOiJjb250YWluZXJfMDE3cnhCTmVqOHpYWG01SDZWaFBMTFhWLS13aWdnbGUtLTI1NDgyNyJ9.BITCA-W5StlsHDLDtNmrFnbJ07LcFxibpu7bQxbDMDLw74BgdRjyx_RlQxqZX1M9rjJUbgzTHlV_DGWoTv0olg"
#JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6Iks3dlRfYUVsdXIySGdsYVJ0QWJ0UThDWDU4dFFqODZIRjJlX1VsSzZkNEEifQ.eyJpc3MiOiJhbnRocm9waWMtZWdyZXNzLWNvbnRyb2wiLCJvcmdhbml6YXRpb25fdXVpZCI6ImE1YTZkNDI0LTEyMDUtNGVkNi1iODcxLWM3MjI5MDUxN2QyOSIsImlhdCI6MTc3MTYyNjY5MCwiZXhwIjoxNzcxNjQxMDkwLCJhbGxvd2VkX2hvc3RzIjoiKi5haSwqLmNvbSwqLmlvLCoubmUsKi5uZXQsYXBpLmFudGhyb3BpYy5jb20sYXJjaGl2ZS51YnVudHUuY29tLGNyYXRlcy5pbyxmaWxlcy5weXRob25ob3N0ZWQub3JnLGdpdGh1Yi5jb20saW5kZXguY3JhdGVzLmlvLG5wbWpzLmNvbSxucG1qcy5vcmcscHlwaS5vcmcscHl0aG9uaG9zdGVkLm9yZyxyZWdpc3RyeS5ucG1qcy5vcmcscmVnaXN0cnkueWFybnBrZy5jb20sc2VjdXJpdHkudWJ1bnR1LmNvbSxzdGF0aWMuY3JhdGVzLmlvLHd3dy5ucG1qcy5jb20sd3d3Lm5wbWpzLm9yZyx5YXJucGtnLmNvbSIsImlzX2hpcGFhX3JlZ3VsYXRlZCI6ImZhbHNlIiwiaXNfYW50X2hpcGkiOiJmYWxzZSIsInVzZV9lZ3Jlc3NfZ2F0ZXdheSI6InRydWUiLCJjb250YWluZXJfaWQiOiJjb250YWluZXJfMDFVeGoyTDgxTlFCa0d0OHNVZEhYOVQ4LS13aWdnbGUtLTMyMGRmNyJ9.Tl1xCYF3Xj0jZwsQAMiRw81jqyfl1-l-qdvccq7VK-vlBfpGpb8dQ8QUOHmBTNphj1GbC8C2a2SxsOKhuTD_xw"
TARGET = "google.com"
PROXY = ("21.0.0.243", 15004)

import base64, json, socket

def _b64(s):
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))

def test_jwt_with_proxy(jwt_token=None, target=None, proxy=None, container_id_override=None):
    """Send CONNECT to proxy with JWT, print status + response, return dict with status_line, headers, body, ok, error."""
    jwt_token = jwt_token or JWT
    target = target or TARGET
    proxy = proxy or PROXY
    out = {"status_line": None, "headers": {}, "body": b"", "ok": False, "error": None}
    try:
        j = jwt_token if jwt_token.startswith("jwt_") else f"jwt_{jwt_token}"
        auth = base64.b64encode(f"{user}:{j}".encode()).decode()
        req = f"CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        print(f"JWT kid={h.get('kid')} container={cid} target={target} proxy={proxy}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(proxy)
        sock.sendall(req.encode())
        print(f"Sent {len(req)} bytes")
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = sock.recv(4096)
            if not chunk: break
            raw += chunk
        sock.close()
        idx = raw.find(b"\r\n\r\n")
        head = raw[:idx] if idx >= 0 else raw
        out["body"] = raw[idx + 4:] if idx >= 0 else b""
        print("FULL BODY RESPONSE HERE", raw)
        lines = head.decode("utf-8", errors="ignore").split("\r\n")
        out["status_line"] = lines[0] if lines else ""
        for line in lines[1:]:
            if ":" in line: k, v = line.split(":", 1); out["headers"][k.strip().lower()] = v.strip()
        print(out["status_line"], dict(out["headers"]), out["body"][:200] if out["body"] else "")
        out["ok"] = "200" in (out["status_line"] or "")
        if out["ok"]: print("OK SUCCESS")
        else: print("X", out["headers"].get("x-deny-reason", "fail"))
    except Exception as e: out["error"] = str(e); print("X", e)
    return out

if __name__ == "__main__":
    test_jwt_with_proxy()
