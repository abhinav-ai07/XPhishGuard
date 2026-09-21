import os
import requests
import base64

def query_virustotal(url: str) -> int:
    """
    Queries VirusTotal v3 API for the number of malicious detections.
    If VT_API_KEY is not in environment or if request fails, returns 0.
    """
    clean_url = url.strip().lower()

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
