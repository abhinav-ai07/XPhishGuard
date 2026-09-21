import os
import sys

# Ensure backend root is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from predict import predict_url

test_cases = [
    {
        "category": "SAFE: Standard youtube.com",
        "url": "https://youtube.com",
        "expected_phishing": False,
    },
    {
        "category": "SAFE: YouTube Watch URL",
        "url": "https://www.youtube.com/watch?v=I-cNgWWzZuI&list=RDI-cNgWWzZuI&start_radio=1",
        "expected_phishing": False,
    },
    {
        "category": "SAFE: netflix.com",
        "url": "https://www.netflix.com",
        "expected_phishing": False,
    },
    {
        "category": "SAFE: google.com",
        "url": "https://www.google.com",
        "expected_phishing": False,
    },
    {
        "category": "SAFE: github.com",
        "url": "https://github.com",
        "expected_phishing": False,
    },
    {
        "category": "PHISHING: youtube-security-alert.xyz",
        "url": "https://youtube-security-alert.xyz",
        "expected_phishing": True,
    },
    {
        "category": "PHISHING: netfliix-login-auth.net",
        "url": "https://netfliix-login-auth.net",
        "expected_phishing": True,
    },
    {
        "category": "PHISHING: paypal-verification-secure-login.com",
        "url": "https://paypal-verification-secure-login.com",
        "expected_phishing": True,
    },
    {
        "category": "PHISHING: adult/porn scam URL",
        "url": "https://adult-dating-porn-webcam-leak.top",
        "expected_phishing": True,
    },
]


def run_tests():
    print("\n=======================================================")
    print("      XPHISHGUARD AI - CONTEXT-AWARE VERIFICATION")
    print("=======================================================\n")

    passed_tests = 0

    for index, case in enumerate(test_cases, start=1):
        print(f"CASE {index}: {case['category']}")
        print(f"  URL     : {case['url']}")
        print(f"  Expected: {'PHISHING' if case['expected_phishing'] else 'SAFE'}")

        try:
            result = predict_url(case["url"])
            detected_phishing = result["is_phishing"]
            pred_text = "PHISHING" if detected_phishing else "SAFE"
            confidence = result["confidence_score"] * 100

            print(f"  Detected: {pred_text} (Confidence: {confidence:.2f}%)")

            signals = result.get("triggered_signals", [])
            print(f"  Signals : {', '.join(signals) if signals else 'None'}")

            if detected_phishing == case["expected_phishing"]:
                print("  STATUS  : PASSED")
                passed_tests += 1
            else:
                print("  STATUS  : FAILED")
        except Exception as exc:
            print(f"  STATUS  : ERROR - {exc}")

        print("-" * 55)

    print("\n=================== VERIFICATION REPORT ===================")
    print(f"  Total tests executed: {len(test_cases)}")
    print(f"  Tests passed        : {passed_tests} / {len(test_cases)}")
    print(f"  Success Rate        : {(passed_tests / len(test_cases)) * 100:.2f}%")
    print("===========================================================\n")
    return passed_tests == len(test_cases)


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
