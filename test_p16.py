import sys
import os
sys.path.append('backend')
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

print('\n=== PHASE 1.6 OBFS/PAYLOAD VERIFICATION ===')
for url, expected in tests:
    res = predict_url(url)
    verdict = 'PHISHING' if res['is_phishing'] else 'SAFE'
    status = 'PASS' if verdict == expected else 'FAIL'
    print(f'[{status}] Expected: {expected} | Detected: {verdict} | Risk: {res["risk_level"]:6} | Conf: {res["confidence_score"]*100:4.1f}% | URL: {url[:45]}')
    if res['triggered_signals']:
        print(f'       Signals: {res["triggered_signals"]}')
