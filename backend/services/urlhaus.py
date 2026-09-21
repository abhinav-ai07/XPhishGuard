import requests

def query_urlhaus(url: str) -> bool:
    """
    Queries URLHaus API to see if the URL is classified as a malware source.
    """
    clean_url = url.strip().lower()

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
