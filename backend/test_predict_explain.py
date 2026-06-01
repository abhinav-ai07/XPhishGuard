import sys
import os

backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.append(backend_dir)

from predict import predict_url

urls = [
    "https://youtube-security-alert.xyz",
    "https://youtube.com"
]

for url in urls:
    print("\n" + "="*80)
    print(f"SCANNING URL: {url}")
    print("="*80)
    try:
        res = predict_url(url)
        print(f"Prediction: {res['analyst_report']['final_verdict'] if 'final_verdict' in res.get('analyst_report', {}) else ('PHISHING' if res['is_phishing'] else 'SAFE')}")
        print(f"Confidence: {res['confidence_score']*100:.2f}%")
        print(f"Risk Level: {res['risk_level']}")
        print("\nTop Contributors:")
        for c in res['top_contributors'][:5]:
            print(f"  * {c['feature']}: {c['impact']}")
        print("\nHuman Explanations:")
        for exp in res['human_explanations'][:3]:
            print(f"  - [{exp['impact_type']}] {exp['message']} ({exp['impact_percent']})")
        print(f"\nAnalyst Summary:\n{res['analyst_summary']}")
        print("\nTimeline:")
        for t in res['threat_timeline']:
            print(f"  Step {t['step']}: {t['event']} -> {t['details']}")
        print("\nVisualizations Generated:")
        print(f"  Keys: {list(res['visualizations'].keys())}")
        for k in res['visualizations'].keys():
            print(f"    - {k} size: {len(res['visualizations'][k])} chars")
    except Exception as e:
        print("ERROR:", e)
        import traceback
        traceback.print_exc()
