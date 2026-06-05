#!/usr/bin/env python3
"""Run the end-to-end demo: blocked secret read when product ON, allowed when OFF."""
import requests
import time

DASH_URL = "http://127.0.0.1:8081"
PROXY_URL = "http://127.0.0.1:8080"
ADMIN_PASSWORD = "admin123"

session = requests.Session()

def login():
    resp = session.get(f"{DASH_URL}/login")
    resp = session.post(f"{DASH_URL}/login", data={"password": ADMIN_PASSWORD}, allow_redirects=False)
    if resp.status_code not in (302, 303):
        raise SystemExit("Login failed; check dashboard is running and password")
    print("Logged into dashboard")


def set_product(enabled: bool):
    resp = session.post(f"{DASH_URL}/api/product", json={"enabled": enabled})
    resp.raise_for_status()
    print(f"Set product enabled={resp.json().get('enabled')}")


def run_secret_test():
    payload = {"tool_name": "filesystem.read", "scenario": "disallowed", "arguments": None}
    resp = session.post(f"{DASH_URL}/api/tests/run", json=payload)
    resp.raise_for_status()
    return resp.json()


if __name__ == '__main__':
    print("Starting end-to-end demo")
    login()

    print("--- Running with product ON (should be blocked) ---")
    set_product(True)
    time.sleep(0.5)
    result_on = run_secret_test()
    print("Result (ON):", result_on.get('actual_decision'), result_on.get('decision_reason_code'))

    print("--- Running with product OFF (should be allowed) ---")
    set_product(False)
    time.sleep(0.5)
    result_off = run_secret_test()
    print("Result (OFF):", result_off.get('actual_decision'), result_off.get('decision_reason_code'))

    print('\nDemo complete. Use the dashboard Tests tab to inspect traces and events.')
