import sys
import os

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from predict import predict_url

urls = [
    "https://youtube-security-alert.xyz",
    "https://youtube.com"
]

def run_tests():
    for url in urls:
        print("\n" + "=" * 80)
        print(f"SCANNING URL: {url}")
        print("=" * 80)
        try:
            res = predict_url(url)
            print(f"Prediction: {res.get('analyst_report', {}).get('final_verdict', ('PHISHING' if res['is_phishing'] else 'SAFE'))}")
            print(f"Confidence: {res['confidence_score'] * 100:.2f}%")
            print(f"Risk Level: {res['risk_level']}")
            print("\nTop Contributors:")
            for c in res.get('top_contributors', [])[:5]:
                print(f"  * {c['feature']}: {c['impact']}")
            print("\nHuman Explanations:")
            for exp in res.get('human_explanations', [])[:3]:
                print(f"  - [{exp['impact_type']}] {exp['message']} ({exp['impact_percent']})")
            print(f"\nAnalyst Summary:\n{res.get('analyst_summary')}")
            print("\nTimeline:")
            for t in res.get('threat_timeline', []):
                print(f"  Step {t['step']}: {t['event']} -> {t['details']}")
            print("\nVisualizations Generated:")
            print(f"  Keys: {list(res.get('visualizations', {}).keys())}")
            for k in res.get('visualizations', {}).keys():
                print(f"    - {k} size: {len(res['visualizations'][k])} chars")
        except Exception as e:
            print("ERROR:", e)
            import traceback
            traceback.print_exc()
            return False
    return True

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
