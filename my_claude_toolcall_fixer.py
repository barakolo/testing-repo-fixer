#!/usr/bin/env python3
# CODE START: safe, basic testing only — upload/download + proxy (hardcoded JWT). ANTHROPIC_API_KEY for upload/download.
import os, sys
try: import requests
except ImportError: print("pip install requests", file=sys.stderr); sys.exit(1)


# Proxy test: hardcoded (no JWT decode). Update CONTAINER_ID when JWT changes.
JWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6Iks3dlRfYUVsdXIySGdsYVJ0QWJ0UThDWDU4dFFqODZIRjJlX1VsSzZkNEEifQ.eyJpc3MiOiJhbnRocm9waWMtZWdyZXNzLWNvbnRyb2wiLCJvcmdhbml6YXRpb25fdXVpZCI6ImE1YTZkNDI0LTEyMDUtNGVkNi1iODcxLWM3MjI5MDUxN2QyOSIsImlhdCI6MTc3MTYzMDgzMywiZXhwIjoxNzcxNjQ1MjMzLCJhbGxvd2VkX2hvc3RzIjoiKi5haSwqLmNvbSwqLmlvLCoubmUsKi5uZXQsYXBpLmFudGhyb3BpYy5jb20sYXJjaGl2ZS51YnVudHUuY29tLGNyYXRlcy5pbyxmaWxlcy5weXRob25ob3N0ZWQub3JnLGdpdGh1Yi5jb20saW5kZXguY3JhdGVzLmlvLG5wbWpzLmNvbSxucG1qcy5vcmcscHlwaS5vcmcscHl0aG9uaG9zdGVkLm9yZyxyZWdpc3RyeS5ucG1qcy5vcmcscmVnaXN0cnkueWFybnBrZy5jb20sc2VjdXJpdHkudWJ1bnR1LmNvbSxzdGF0aWMuY3JhdGVzLmlvLHd3dy5ucG1qcy5jb20sd3d3Lm5wbWpzLm9yZyx5YXJucGtnLmNvbSIsImlzX2hpcGFhX3JlZ3VsYXRlZCI6ImZhbHNlIiwiaXNfYW50X2hpcGkiOiJmYWxzZSIsInVzZV9lZ3Jlc3NfZ2F0ZXdheSI6InRydWUiLCJjb250YWluZXJfaWQiOiJjb250YWluZXJfMDE3cnhCTmVqOHpYWG01SDZWaFBMTFhWLS13aWdnbGUtLTI1NDgyNyJ9.BITCA-W5StlsHDLDtNmrFnbJ07LcFxibpu7bQxbDMDLw74BgdRjyx_RlQxqZX1M9rjJUbgzTHlV_DGWoTv0olg"
CONTAINER_ID = "container_017rxBNej8zXXm5H6VhPLLXV--wiggle--254827"
TARGET = "google.com"
PROXY = ("21.0.0.243", 15004)

import base64, socket, ssl

def test_jwt_with_proxy():
    j = JWT if JWT.startswith("jwt_") else "jwt_" + JWT
    auth = base64.b64encode(f"{CONTAINER_ID}:{j}".encode()).decode()
    req = f"CONNECT {TARGET}:443 HTTP/1.1\r\nHost: {TARGET}:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect(PROXY)
    sock.sendall(req.encode())
    raw = b""
    while b"\r\n\r\n" not in raw:
        c = sock.recv(4096)
        if not c: break
        raw += c
    first = (raw.split(b"\r\n")[0] or b"").decode("utf-8", errors="ignore")
    if "200" not in first:
        print(first, raw.decode("utf-8", errors="replace"))
        sock.close()
        return
    tls = ssl.create_default_context().wrap_socket(sock, server_hostname=TARGET)
    tls.sendall(f"GET / HTTP/1.1\r\nHost: {TARGET}\r\nConnection: close\r\n\r\n".encode())
    body = b""
    while True:
        c = tls.recv(4096)
        if not c: break
        body += c
    tls.close()
    print(body.decode("utf-8", errors="replace"))

if __name__ == "__main__":
    test_jwt_with_proxy()
