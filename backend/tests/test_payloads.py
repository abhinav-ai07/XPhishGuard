import sys
import os

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from predict import predict_url

tests = [
    # Safe 
    ('https://www.youtube.com/watch?v=dQw4w9WgXcQ', 'SAFE'),
    ('https://github.com/torvalds/linux/issues/1234', 'SAFE'),
    ('https://chatgpt.com/share/abc123', 'SAFE'),
    ('https://docs.google.com/document/d/1abc/edit', 'SAFE'),
    ('https://leetcode.com/problems/two-sum/', 'SAFE'),
    
    # Suspicious / Malformed (Even on Trusted Domains)
    ('https://www.youtube.com/watch?v=l!}0aaaa', 'PHISHING'),
    ('https://www.youtube.com/watch?v=<script>', 'PHISHING'),
    ('https://google.com/%3Cscript%3E', 'PHISHING'),
    ('https://y0utube.com/watch?v=abc', 'PHISHING'),
    ('https://github.com/login?redirect=javascript:alert(1)', 'PHISHING')
]

def run_tests():
    print('\n=== ADVANCED OBFUSCATION / PAYLOAD TEST SUITE ===')
    passed = 0
    for url, expected in tests:
        res = predict_url(url)
        verdict = 'PHISHING' if res['is_phishing'] else 'SAFE'
        status = 'PASS' if verdict == expected else 'FAIL'
        if status == 'PASS':
            passed += 1
        print(f'[{status}] Expected: {expected:8} | Detected: {verdict:8} | Risk: {res["risk_level"]:6} | Conf: {res["confidence_score"]*100:4.1f}% | URL: {url[:45]}')
        if res.get('triggered_signals'):
            print(f'       Signals: {res["triggered_signals"]}')
    print(f"\nResult: {passed}/{len(tests)} passed.")
    return passed == len(tests)

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
