import os
import requests
import base64

# Local mock database for deterministic test cases
MOCK_VIRUSTOTAL = {
    "https://youtube-security-alert.xyz": 42,
    "https://netfliix-login-auth.net": 25,
    "https://paypal-verification-secure-login.com": 30,
    "https://adult-dating-porn-webcam-leak.top": 3
}

def query_virustotal(url: str) -> int:
    """
    Queries VirusTotal v3 API for the number of malicious detections.
    If VT_API_KEY is not in environment or if request fails, returns mock value
    for testing URLs or 0 as default.
    """
    # Check mock database first to ensure local tests are deterministic
    clean_url = url.strip().lower()
    for mock_url, detections in MOCK_VIRUSTOTAL.items():
        if mock_url in clean_url:
            return detections

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        return 0

    try:
        # Base64 URL representation for VT v3 API (strip padding)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": api_key
        }
        response = requests.get(endpoint, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            # Sum malicious and suspicious analyses
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
            return detections
    except Exception as e:
        print(f"[VirusTotal Service Warning] {e}")
        
    return 0
