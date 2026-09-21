import sys
import os

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from predict import predict_url

test_urls = [
    "https://youtube-security-alert.xyz",
    "https://netfliix-login-auth.net",
    "https://paypal-verification-secure-login.com",
    "https://adult-dating-porn-webcam-leak.top",
    "https://youtube.com"
]

def run_tests():
    print("======================================================================")
    print("      XPHISHGUARD AI — THREAT INTEL INTEGRATION TEST")
    print("======================================================================\n")

    for url in test_urls:
        print(f"SCANNING: {url}")
        try:
            res = predict_url(url)
            print(f"  Verdict       : {res['risk_level']} RISK ({'PHISHING' if res['is_phishing'] else 'SAFE'})")
            print(f"  Confidence    : {res['confidence_score']*100:.1f}%")
            
            # Threat Intel Block
            ti = res.get('threat_intelligence', {})
            vt_det = ti.get('virustotal', {}).get('detections', 0)
            print(f"  Threat Intel  : VT Detections={vt_det}, PhishTank={ti.get('phishtank')}, OpenPhish={ti.get('openphish')}, URLHaus={ti.get('urlhaus')}")
            
            # Signals
            print(f"  Signals       : {res.get('triggered_signals')}")
            
            # Short Explanations
            print("  Why Flagged (Concise):")
            for exp in res.get('human_explanations', []):
                print(f"    • {exp['message']} ({exp['impact_percent']})")
                
            print(f"  Timeline Steps: {len(res.get('threat_timeline', []))} recorded.")
            print("-" * 70)
        except Exception as e:
            print(f"  ERROR scanning {url}: {e}")
            import traceback
            traceback.print_exc()
            return False

    print("Verification complete.")
    return True

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
