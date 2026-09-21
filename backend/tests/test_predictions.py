import sys
import os

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from predict import predict_url

safe_urls = [
    "https://google.com",
    "https://github.com",
    "https://chatgpt.com",
    "https://leetcode.com",
    "https://youtube.com",
    "https://cricbuzz.com",
    "https://espncricinfo.com",
    "https://stackoverflow.com",
    "https://huggingface.co",
    "https://amazon.com"
]

phishing_urls = [
    "http://paypal-login-security.xyz",
    "http://micr0soft-account-login.ru",
    "http://secure-google-login-update.tk",
    "http://apple-id-verification-login.xyz"
]

def run_tests():
    print("TESTING SAFE URLS:")
    for url in safe_urls:
        try:
            res = predict_url(url)
            print(f"[{res['risk_level']}] ({res['confidence_score']*100:.1f}%) {url}")
        except Exception as e:
            print(f"[ERROR] {url}: {e}")

    print("\nTESTING PHISHING URLS:")
    for url in phishing_urls:
        try:
            res = predict_url(url)
            brand = res.get('brand_detection', {}).get('likely_target_brand')
            attack = res.get('attack_classification', {}).get('primary_attack_type')
            print(f"[{res['risk_level']}] ({res['confidence_score']*100:.1f}%) {url} - Brand: {brand} - Attack: {attack}")
        except Exception as e:
            print(f"[ERROR] {url}: {e}")
    return True

if __name__ == "__main__":
    run_tests()
