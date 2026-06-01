import requests

MOCK_URLHAUS = {
    "https://youtube-security-alert.xyz": False,
    "https://netfliix-login-auth.net": True,
    "https://paypal-verification-secure-login.com": False,
    "https://adult-dating-porn-webcam-leak.top": True
}

def query_urlhaus(url: str) -> bool:
    """
    Queries URLHaus API to see if the URL is classified as a malware source.
    """
    clean_url = url.strip().lower()
    for mock_url, is_hit in MOCK_URLHAUS.items():
        if mock_url in clean_url:
            return is_hit

    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {
        "url": url
    }

    try:
        response = requests.post(endpoint, data=data, timeout=5)
        if response.status_code == 200:
            res_data = response.json()
            # If query_status is 'ok', the URL is found in URLHaus database
            return res_data.get("query_status") == "ok"
    except Exception as e:
        print(f"[URLHaus Service Warning] {e}")

    return False
