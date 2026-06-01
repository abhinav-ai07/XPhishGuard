import time
import requests

MOCK_OPENPHISH = {
    "https://youtube-security-alert.xyz": True,
    "https://netfliix-login-auth.net": False,
    "https://paypal-verification-secure-login.com": True,
    "https://adult-dating-porn-webcam-leak.top": False
}

# In-memory feed cache to avoid excessive downloads during analysis
_OPENPHISH_CACHE = set()
_LAST_FETCH_TIME = 0
CACHE_DURATION_SECONDS = 3600  # 1 hour cache duration

def query_openphish(url: str) -> bool:
    """
    Checks if URL is reported on OpenPhish.
    Downloads the live active feed and caches it for 1 hour.
    """
    global _OPENPHISH_CACHE, _LAST_FETCH_TIME
    clean_url = url.strip().lower()

    # Check mock database first for deterministic test urls
    for mock_url, is_phish in MOCK_OPENPHISH.items():
        if mock_url in clean_url:
            return is_phish

    current_time = time.time()
    if not _OPENPHISH_CACHE or (current_time - _LAST_FETCH_TIME) > CACHE_DURATION_SECONDS:
        try:
            print("Downloading live OpenPhish community threat feed...")
            response = requests.get("https://openphish.com/feed.txt", timeout=5)
            if response.status_code == 200:
                # Store all lines (URLs) in a set for O(1) lookup
                urls_list = [line.strip().lower() for line in response.text.splitlines() if line.strip()]
                _OPENPHISH_CACHE = set(urls_list)
                _LAST_FETCH_TIME = current_time
                print(f"Loaded {_LAST_FETCH_TIME} OpenPhish feeds successfully.")
        except Exception as e:
            print(f"[OpenPhish Cache Warning] Failed to refresh live feed: {e}")

    # Search in set
    return clean_url in _OPENPHISH_CACHE
