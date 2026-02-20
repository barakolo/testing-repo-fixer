#!/usr/bin/env python3
"""
Interactive JWT Token Tester
Accepts JWT tokens from stdin and tests them against the proxy
"""

import os
import base64
import json
import socket
import sys
import time
from datetime import datetime

def decode_jwt(jwt_token):
    """Decode JWT token"""
    if jwt_token.startswith('jwt_'):
        jwt_token = jwt_token[4:]
    
    parts = jwt_token.split('.')
    if len(parts) != 3:
        return None, None, None
    
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        signature = parts[2]
        return header, payload, signature
    except Exception as e:
        print(f"✗ Decode error: {e}")
        return None, None, None

def test_jwt_with_proxy(jwt_token, target_domain="google.com", 
                       container_id_override=None):
    """Test JWT token against proxy"""
    
    print("\n" + "═" * 80)
    print("TESTING JWT TOKEN")
    print("═" * 80)
    
    # Decode
    header, payload, signature = decode_jwt(jwt_token)
    
    if not header or not payload:
        print("✗ Failed to decode JWT")
        return
    
    # Display JWT info
    print("\n[1] JWT Token Information")
    print("─" * 80)
    print(f"Algorithm:    {header.get('alg')} (ES256 = ECDSA P-256)")
    print(f"Key ID:       {header.get('kid')}")
    print(f"\nIssuer:       {payload.get('iss')}")
    print(f"Org UUID:     {payload.get('organization_uuid')}")
    print(f"Container ID: {payload.get('container_id')}")
    
    iat = payload.get('iat', 0)
    exp = payload.get('exp', 0)
    now = int(time.time())
    
    print(f"\nIssued:       {datetime.fromtimestamp(iat)}")
    print(f"Expires:      {datetime.fromtimestamp(exp)}")
    print(f"Current:      {datetime.fromtimestamp(now)}")
    
    time_left = exp - now
    if time_left > 0:
        hours = time_left // 3600
        mins = (time_left % 3600) // 60
        print(f"Status:       ✓ Valid for {hours}h {mins}m")
    else:
        print(f"Status:       ✗ EXPIRED")
    
    # Check allowed hosts
    allowed_hosts = payload.get('allowed_hosts', '').split(',')
    print(f"\n[2] Allowed Hosts ({len(allowed_hosts)} domains)")
    print("─" * 80)
    for i, host in enumerate(allowed_hosts[:20], 1):
        print(f"  {i:2d}. {host}")
    if len(allowed_hosts) > 20:
        print(f"  ... and {len(allowed_hosts) - 20} more")
    
    is_allowed = target_domain in allowed_hosts
    print(f"\nTarget: {target_domain}")
    print(f"Status: {'✓ IN WHITELIST' if is_allowed else '✗ NOT IN WHITELIST'}")
    
    # Determine container ID to use
    if container_id_override:
        use_container_id = container_id_override
        print(f"\n[3] Using Custom Container ID")
        print("─" * 80)
        print(f"JWT container_id: {payload.get('container_id')}")
        print(f"Using:            {use_container_id}")
    else:
        use_container_id = payload.get('container_id')
        print(f"\n[3] Using JWT Container ID")
        print("─" * 80)
        print(f"Container ID: {use_container_id}")
    
    username = f"container_{use_container_id}"
    
    # Build request
    print(f"\n[4] Building Proxy Request")
    print("─" * 80)
    
    if not jwt_token.startswith('jwt_'):
        jwt_token_full = f"jwt_{jwt_token}"
    else:
        jwt_token_full = jwt_token
    
    auth_string = f"{username}:{jwt_token_full}"
    auth_b64 = base64.b64encode(auth_string.encode()).decode()
    
    print(f"Username:     {username}")
    print(f"Password:     {jwt_token_full[:30]}...")
    print(f"Base64 auth:  {len(auth_b64)} bytes")
    print(f"Proxy:        21.0.0.243:15004")
    print(f"Target:       {target_domain}:443")
    
    connect_request = (
        f"CONNECT {target_domain}:443 HTTP/1.1\r\n"
        f"Host: {target_domain}:443\r\n"
        f"Proxy-Authorization: Basic {auth_b64}\r\n"
        f"User-Agent: JWT-Interactive-Tester/1.0\r\n"
        f"\r\n"
    )
    
    print(f"\n[5] Sending Request to Proxy")
    print("─" * 80)
    print(f"Connecting to 21.0.0.243:15004...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("21.0.0.243", 15004))
        print(f"✓ TCP connected")
        
        sock.sendall(connect_request.encode())
        print(f"✓ Sent {len(connect_request)} bytes")
        
        print(f"\nWaiting for proxy response...")
        
        response_data = b''
        while b'\r\n\r\n' not in response_data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk
        
        response_text = response_data.decode('utf-8', errors='ignore')
        lines = response_text.split('\r\n')
        status_line = lines[0]
        
        print(f"\n[6] Proxy Response")
        print("─" * 80)
        print(f"Status: {status_line}")
        
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
                print(f"  {key.strip()}: {value.strip()}")
            elif line == '':
                break
        
        header_end = response_data.find(b'\r\n\r\n')
        if header_end != -1:
            body = response_data[header_end + 4:]
            if body:
                print(f"\nBody: {body.decode('utf-8', errors='ignore')}")
        
        sock.close()
        
        print(f"\n[7] Result")
        print("─" * 80)
        
        if '200' in status_line:
            print("✓✓✓ SUCCESS!")
            print(f"    JWT token is VALID")
            print(f"    Tunnel established to {target_domain}")
            print(f"    Could send HTTPS traffic through tunnel")
        elif '403' in status_line:
            reason = headers.get('x-deny-reason', 'unknown')
            print("✗✗✗ BLOCKED!")
            print(f"    HTTP Status: 403 Forbidden")
            print(f"    Deny Reason: {reason}")
            
            if reason == 'host_not_allowed':
                print(f"    → Domain '{target_domain}' not in JWT whitelist")
            elif reason == 'invalid_token':
                print(f"    → JWT signature verification failed")
            elif reason == 'expired_token':
                print(f"    → JWT token has expired")
            elif reason == 'container_mismatch':
                print(f"    → Container ID doesn't match JWT claim")
        elif '401' in status_line:
            print("✗✗✗ AUTHENTICATION FAILED!")
            print(f"    HTTP Status: 401 Unauthorized")
            print(f"    JWT validation failed")
            print(f"    Possible reasons:")
            print(f"      • Invalid signature (modified JWT)")
            print(f"      • Token expired")
            print(f"      • Wrong issuer")
            print(f"      • Malformed JWT")
        else:
            print(f"? Unexpected response: {status_line}")
        
    except socket.timeout:
        print("✗ Timeout connecting to proxy")
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "═" * 80)


def main():
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║              INTERACTIVE JWT TOKEN TESTER                                 ║
║                                                                           ║
║  Test JWT tokens from any source against the Envoy proxy                 ║
╚═══════════════════════════════════════════════════════════════════════════╝

USAGE:
  Paste a JWT token and press Enter to test it against google.com
  
  Commands:
    jwt <token>              - Test token against google.com
    jwt <token> <domain>     - Test token against specific domain
    help                     - Show this help
    quit / exit              - Exit the program

EXAMPLES:
  jwt eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiI...
  jwt jwt_eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiI... pypi.org
  
You can test:
  • Current container's JWT token
  • JWT tokens from other machines (will show container ID mismatch)
  • Modified JWT tokens (will show signature failure)
  • Expired JWT tokens (will show expiry failure)

""")
    
    # Get current token for reference
    current_proxy = os.environ.get('HTTPS_PROXY', '')
    if 'jwt_' in current_proxy:
        current_jwt = current_proxy.split('jwt_')[1].split('@')[0]
        header, payload, _ = decode_jwt(current_jwt)
        if header and payload:
            print("[Current Container's JWT]")
            print(f"  Container: {payload.get('container_id')}")
            print(f"  Expires:   {datetime.fromtimestamp(payload.get('exp', 0))}")
            print(f"  Hosts:     {len(payload.get('allowed_hosts', '').split(','))} domains")
            print()
    
    print("─" * 80)
    print("Ready! Paste JWT token below:")
    print("─" * 80)
    
    while True:
        try:
            line = input("\n> ").strip()
            
            if not line:
                continue
            
            if line.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            
            if line.lower() == 'help':
                print("\nCommands:")
                print("  jwt <token>              - Test token")
                print("  jwt <token> <domain>     - Test token against domain")
                print("  quit / exit              - Exit")
                continue
            
            parts = line.split()
            
            if len(parts) == 0:
                continue
            elif len(parts) == 1:
                # Just JWT token, test against google.com
                jwt_token = parts[0]
                target_domain = "google.com"
            elif len(parts) == 2:
                # JWT token and domain
                jwt_token = parts[0]
                target_domain = parts[1]
            else:
                print("✗ Usage: jwt <token> [domain]")
                continue
            
            # Remove 'jwt' prefix if user typed it
            if jwt_token.lower() == 'jwt':
                continue
            
            test_jwt_with_proxy(jwt_token, target_domain)
            
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except EOFError:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"✗ Error: {e}")

if __name__ == "__main__":
    main()
