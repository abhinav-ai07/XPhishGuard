import os
import requests

MOCK_PHISHTANK = {
    "https://youtube-security-alert.xyz": True,
    "https://netfliix-login-auth.net": True,
    "https://paypal-verification-secure-login.com": True,
    "https://adult-dating-porn-webcam-leak.top": False
}

def query_phishtank(url: str) -> bool:
    """
    Checks if URL is reported on PhishTank.
    Uses PhishTank API or mock fallback for local tests.
    """
    clean_url = url.strip().lower()
    for mock_url, is_phish in MOCK_PHISHTANK.items():
        if mock_url in clean_url:
            return is_phish

    api_key = os.getenv("PHISHTANK_API_KEY")
    # PhishTank API endpoint
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    payload = {
        "url": url,
        "format": "json"
    }
    if api_key:
        payload["app_key"] = api_key

    headers = {
        "User-Agent": "phishtank/XPhishGuard-AI-Threat-Intel"
    }

    try:
        response = requests.post(endpoint, data=payload, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            results = data.get("results", {})
            return results.get("in_database", False) and results.get("valid", False)
    except Exception as e:
        print(f"[PhishTank Service Warning] {e}")

    return False
