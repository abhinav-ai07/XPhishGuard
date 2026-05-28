"""
XPhishGuard AI — Phase 1.5 Adversarial Training Pipeline
=========================================================

Changes from Phase 1:
1.  24-feature schema  (repeated_char_max removed, 6 semantic categories added)
2.  Expanded trusted-domain baseline injection  (20 brands × 15 URL variants = 300 safe samples)
3.  Safe long-URL augmentation  (60 realistic long URLs from major platforms)
4.  Modern phishing augmentation  (60 realistic attack patterns)
5.  Adversarial protocol augmentation  (breaks HTTPS = Safe shortcut)
6.  3-model competition  (RF / XGBoost / LightGBM)
7.  Detailed feature importance output
"""

import os
import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, KFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix)

try:
    from xgboost import XGBClassifier
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

try:
    from lightgbm import LGBMClassifier
    LGBM_AVAILABLE = True
except ImportError:
    LGBM_AVAILABLE = False

from feature_engineering import get_feature_list

# ──────────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "url_length", "dot_count", "hyphen_count", "has_https",
    "has_at_symbol", "is_ip_address", "is_risky_tld", "brand_impersonation",
    "domain_entropy", "digit_ratio", "subdomain_count", "token_count",
    "keyword_density", "is_shortened", "has_redirect_params",
    "has_scam_keywords", "is_trusted_domain", "is_institutional_tld",
    "is_search_engine", "is_ai_platform", "is_streaming_platform",
    "is_coding_platform", "is_educational_platform", "is_social_platform",
]

# ──────────────────────────────────────────────────────────────────
#  AUGMENTATION DATA
# ──────────────────────────────────────────────────────────────────

# 60 safe long/complex URLs from high-reputation platforms
SAFE_AUGMENTATION = [
    # YouTube
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.youtube.com/watch?v=o-7b6ctrQX0&list=PLH0Szn1yYNeef2AIsB0oKDFSWdJKdSCMq&index=3",
    "https://www.youtube.com/results?search_query=machine+learning+tutorial",
    "https://youtube.com/playlist?list=PLH0Szn1yYNeef2AIsB0oKDFSWdJKdSCMq",
    "https://www.youtube.com/watch?v=aircAruvnKk&t=245s",
    "https://www.youtube.com/channel/UCVHFbw7woebKtfvug_Nobe",
    # GitHub
    "https://github.com/torvalds/linux/blob/master/kernel/sched/core.c",
    "https://github.com/features/copilot",
    "https://github.com/issues?q=is%3Aissue+is%3Aopen+label%3Abug",
    "https://github.com/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse",
    "https://raw.githubusercontent.com/openai/gpt-2/master/src/model.py",
    "https://github.com/scikit-learn/scikit-learn/pull/28921",
    "https://github.com/orgs/microsoft/repositories?type=public&language=python",
    # ChatGPT / OpenAI
    "https://chatgpt.com/share/abc123def456ghi789jkl000",
    "https://chat.openai.com/c/abc123-def456-ghi789-xyz000",
    "https://platform.openai.com/docs/api-reference/completions",
    "https://openai.com/research/gpt-4",
    # Google
    "https://docs.google.com/document/d/1abc123def456ghi789jkl/edit?usp=sharing",
    "https://drive.google.com/file/d/1abc123def456ghi789/view?usp=sharing",
    "https://www.google.com/search?q=phishing+detection+machine+learning&hl=en",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://www.google.co.in/maps/place/Bangalore/@12.9715987,77.5945627",
    # LeetCode
    "https://leetcode.com/problems/two-sum/description/",
    "https://leetcode.com/problems/longest-substring-without-repeating-characters/",
    "https://leetcode.com/contest/weekly-contest-350/ranking/1/",
    "https://leetcode.com/discuss/general-discussion/1113154/my-experience-with-faang",
    "https://leetcode.com/problemset/?difficulty=MEDIUM&page=1&topicSlugs=dynamic-programming",
    # Netflix
    "https://www.netflix.com/watch/81004016",
    "https://www.netflix.com/title/80057281",
    "https://www.netflix.com/browse/genre/5763",
    # Spotify
    "https://open.spotify.com/playlist/37i9dQZF1DXcBWIGoYBM5M",
    "https://open.spotify.com/album/4aawyAB9vmqN3uQ7FjRGTy?si=abc123",
    "https://open.spotify.com/track/4iV5W9uYEdYUVa79Axb7Rh",
    # Amazon
    "https://www.amazon.com/dp/B08N5WRWNW/ref=sr_1_1?keywords=laptop&qid=1234567890&s=electronics",
    "https://www.amazon.in/Laptop-Intel-Core-i7/dp/B08N5WRWNW?th=1&psc=1",
    # Kaggle
    "https://www.kaggle.com/code/alexisbcook/titanic-tutorial/notebook",
    "https://www.kaggle.com/datasets/uciml/iris",
    "https://www.kaggle.com/competitions/titanic/overview",
    # Coursera
    "https://www.coursera.org/learn/machine-learning-specialization",
    "https://www.coursera.org/professional-certificates/ibm-data-science",
    "https://www.coursera.org/account/accomplishments/verify/ABCDEF123456",
    # StackOverflow
    "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-an-unsorted-array",
    "https://stackoverflow.com/questions/tagged/python?tab=Votes&page=2",
    # Educational Institutions
    "http://www.rvce.edu.in/admissions",
    "https://www.iitb.ac.in/en/academics/undergraduate-admission",
    "https://www.mit.edu/research/",
    "https://www.stanford.edu/academics/",
    "https://www.harvard.edu/programs/",
    # LinkedIn
    "https://www.linkedin.com/jobs/view/3876543210/",
    "https://www.linkedin.com/learning/python-essential-training",
    # Reddit
    "https://www.reddit.com/r/MachineLearning/comments/abc123/paper_discussion/",
    "https://www.reddit.com/r/learnprogramming/comments/def456/how_to_learn_python/",
    # Canva / Notion / Figma
    "https://www.canva.com/design/DAF123abc456def789/edit",
    "https://www.notion.so/Getting-started-a0b1c2d3e4f5a6b7c8d9e0f1",
    "https://www.figma.com/file/abc123def456/Design-System?node-id=0%3A1",
    # Hugging Face
    "https://huggingface.co/models?pipeline_tag=text-classification&sort=downloads",
    "https://huggingface.co/spaces/stabilityai/stable-diffusion",
    # Wikipedia
    "https://en.wikipedia.org/wiki/Phishing#Techniques",
    "https://en.wikipedia.org/wiki/Machine_learning",
]

# 60 modern phishing / scam / impersonation URLs
PHISHING_AUGMENTATION = [
    # YouTube impersonation
    "http://youtube-security-alert.xyz/verify-account",
    "https://youtub3-login-verify.net/signin",
    "https://youtube-premium-upgrade-free.com/claim",
    "http://secure-youtube-account.ml/update",
    "https://youtube-account-suspended-verify.xyz/appeal",
    # Netflix
    "https://netfliix-login-auth.net/verify",
    "http://netflix-billing-update-secure.com/payment",
    "https://netfix-premium-account.xyz/login",
    "http://netflix-account-suspended.net/reactivate",
    "https://netflixx-streaming-renew.ml/pay",
    # Google
    "https://google-docs-shared-alert.xyz/view-document",
    "http://googIe-drive-security-alert.com/verify",
    "https://google-account-suspension-notice.net/appeal",
    "http://mail-google-security-verify.xyz/signin",
    "https://googIe-workspace-alert.com/confirm",
    # PayPal
    "https://paypal-account-verification-alert.com/verify",
    "http://paypaI-secure-login.net/signin",
    "https://paypal-security-centre-verify.xyz/update",
    "http://paypal-billing-resolution.ml/payment",
    "https://paypal-account-limitation-notice.net/resolve",
    # GitHub
    "https://github-authentication-alert.com/verify",
    "http://github-login-verification.net/security",
    "https://github-account-suspension.xyz/appeal",
    "http://github-pr-review-alert.ml/signin",
    # Microsoft
    "https://microsoft-security-team-login.net/verify",
    "http://microsofft-account-alert.com/update",
    "https://microsoft-office365-verify.xyz/signin",
    "http://microsoft-teams-login-verify.net/auth",
    # ChatGPT / OpenAI
    "https://chatgpt-premium-free.xyz/upgrade",
    "http://openai-account-warning.net/verify",
    "https://chatgpt4-free-access.ml/claim",
    "http://openai-premium-upgrade.xyz/payment",
    "https://chatgpt-pro-free-trial.net/register",
    # Banking
    "https://chase-bank-security-alert.xyz/verify",
    "http://wellsfargo-account-update.net/login",
    "https://citibank-security-team-login.com/verify",
    "http://bankofamerica-alert-security.xyz/update",
    "https://hdfc-netbanking-verify-secure.xyz/login",
    # Crypto scam
    "http://bitcoin-free-earn-daily.xyz/claim",
    "https://ethereum-airdrop-claim.ml/bonus",
    "http://crypto-wallet-recovery-verify.net/login",
    "https://binance-bonus-claim-free.xyz/redeem",
    # Fake educational portals
    "https://rvce-student-login-security.xyz/verify",
    "http://iitb-student-portal-secure.net/login",
    "https://coursera-certificate-verify.net/claim",
    "http://udemy-free-courses-claim.xyz/bonus",
    "https://edx-scholarship-verify.ml/apply",
    # Fake AI tools
    "https://chatgpt-free-premium-v4.xyz/upgrade",
    "http://openai-gpt5-beta-access.net/register",
    "https://gemini-pro-free-upgrade.xyz/claim",
    "http://claude-ai-premium-free.ml/register",
    # Streaming scam
    "http://netflix-free-premium.xyz/claim",
    "https://spotify-premium-free-upgrade.ml/claim",
    "http://prime-video-free-account.net/verify",
    "https://hotstar-free-subscription.xyz/claim",
    # Generic verification patterns
    "https://account-verify-secure-update.xyz/step1",
    "http://login-verify-update-secure.net/auth",
    "https://security-alert-account-update.com/verify",
    # Typosquatting
    "https://gooogle-docs-verify.com/document",
    "http://amazoon-prime-account.net/verify",
    "https://linkedln-jobs-apply.xyz/verify",
]


# ──────────────────────────────────────────────────────────────────
#  DATA LOADING
# ──────────────────────────────────────────────────────────────────

def load_and_preprocess_data(csv_path: str):
    print(f"Loading dataset: {csv_path} ...")
    df = pd.read_csv(csv_path)

    # 1. Auto-detect URL column name
    url_col = next(
        (c for c in df.columns if c.lower() == 'url'),
        df.columns[0]
    )

    # 2. Auto-detect label convention
    if 'FILENAME' in df.columns:
        mw_rows = df[df['FILENAME'].astype(str).str.startswith('mw')]
        if len(mw_rows) > 0 and (mw_rows['label'] == 0).mean() > 0.8:
            print("  [Label fix] Inverting labels (0=malicious -> 1=phishing)")
            df['label'] = 1 - df['label']

    # 3. Balanced 20k sample from raw dataset
    if len(df) > 20000:
        safe_df  = df[df['label'] == 0].sample(n=10000, random_state=42)
        phish_df = df[df['label'] == 1].sample(n=10000, random_state=42)
        df = pd.concat([safe_df, phish_df]).sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"  Sampled 20,000 balanced rows (10k safe + 10k phishing)")

    # 4. Trusted-domain baseline injection (20 brands × 15 URL patterns = 300 safe)
    trusted_brands = [
        "youtube", "google", "netflix", "github", "wikipedia", "microsoft",
        "canva", "amazon", "apple", "facebook", "twitter", "linkedin",
        "leetcode", "chatgpt", "openai", "spotify", "kaggle", "coursera",
        "stackoverflow", "notion",
    ]
    url_patterns = [
        "https://{b}.com",
        "https://www.{b}.com",
        "http://{b}.com",
        "https://{b}.com/index.html",
        "https://www.{b}.com/search?q=tutorial&id=123",
        "https://{b}.com/watch?v=o-7b6ctrQX0",
        "https://{b}.com/profile/user-123456",
        "https://{b}.com/about",
        "https://api.{b}.com/v1/status",
        "https://docs.{b}.com/en/getting-started",
        "https://{b}.com/dashboard?tab=overview",
        "https://{b}.com/settings/security",
        "https://app.{b}.com/workspace/abc123",
        "https://{b}.com/problems/two-sum/?difficulty=Easy",
        "https://{b}.com/blog/2024/new-features",
    ]
    trusted_rows = []
    for b in trusted_brands:
        for pat in url_patterns:
            trusted_rows.append({url_col: pat.format(b=b), 'label': 0})
    df_trusted = pd.DataFrame(trusted_rows)
    df = pd.concat([df, df_trusted]).reset_index(drop=True)
    print(f"  Injected {len(df_trusted)} trusted-domain safe baseline rows")

    # 5. Safe long-URL augmentation (60 samples)
    safe_extra = pd.DataFrame({
        url_col: SAFE_AUGMENTATION,
        'label': [0] * len(SAFE_AUGMENTATION)
    })
    df = pd.concat([df, safe_extra]).reset_index(drop=True)
    print(f"  Injected {len(safe_extra)} safe long-URL augmentation rows")

    # 6. Modern phishing augmentation (60 samples)
    phish_extra = pd.DataFrame({
        url_col: PHISHING_AUGMENTATION,
        'label': [1] * len(PHISHING_AUGMENTATION)
    })
    df = pd.concat([df, phish_extra]).reset_index(drop=True)
    print(f"  Injected {len(phish_extra)} modern phishing augmentation rows")

    # 7. Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # 8. Adversarial protocol augmentation (breaks HTTPS = Safe shortcut)
    print("  Applying adversarial protocol augmentation ...")
    urls_out = []
    for idx, row in df.iterrows():
        url   = str(row[url_col])
        label = row['label']
        np.random.seed(idx)
        r = np.random.rand()
        if label == 1 and r < 0.65:          # 65% of phishing → https
            url = "https://" + url[7:] if url.startswith("http://") else url
        elif label == 0 and r < 0.35:        # 35% of safe → http
            url = "http://" + url[8:] if url.startswith("https://") else url
        urls_out.append((url, label))

    # 9. Feature extraction
    print(f"  Extracting features from {len(urls_out)} URLs ...")
    rows = []
    for i, (url, label) in enumerate(urls_out):
        rows.append(get_feature_list(url))
        if (i + 1) % 5000 == 0:
            print(f"    {i+1}/{len(urls_out)} processed")

    X = pd.DataFrame(rows, columns=FEATURE_NAMES)
    y = pd.Series([lbl for _, lbl in urls_out])
    return X, y


# ──────────────────────────────────────────────────────────────────
#  MAIN TRAINING LOOP
# ──────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*55)
    print("  XPHISHGUARD AI — PHASE 1.5 TRAINING PIPELINE")
    print("="*55 + "\n")

    backend_dir = os.path.dirname(os.path.abspath(__file__))
    custom_csv  = os.path.join(backend_dir, "dataset", "datasetphishing.csv")
    csv_path    = custom_csv if os.path.exists(custom_csv) \
                  else os.path.join(backend_dir, "dataset", "phishing.csv")
    models_dir  = os.path.join(backend_dir, "models")
    model_path  = os.path.join(models_dir, "phishing_model.pkl")
    os.makedirs(models_dir, exist_ok=True)

    X, y = load_and_preprocess_data(csv_path)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"\nTrain: {len(X_train)}  |  Test: {len(X_test)}")

    competitors = {
        "Random Forest": RandomForestClassifier(
            n_estimators=150, random_state=42, n_jobs=-1)
    }
    if XGB_AVAILABLE:
        competitors["XGBoost"] = XGBClassifier(
            n_estimators=150, max_depth=6, learning_rate=0.08,
            random_state=42, eval_metric='logloss', n_jobs=-1)
    if LGBM_AVAILABLE:
        competitors["LightGBM"] = LGBMClassifier(
            n_estimators=150, max_depth=6, learning_rate=0.08,
            random_state=42, verbosity=-1, n_jobs=-1)

    kf = KFold(n_splits=5, shuffle=True, random_state=42)
    best_f1, champion_name, champion_model, champion_metrics = 0, None, None, {}

    print("\n--- Model Competition ---")
    for name, clf in competitors.items():
        print(f"\n  [{name}]")
        cv = cross_val_score(clf, X_train, y_train, cv=kf,
                             scoring='accuracy', n_jobs=-1)
        print(f"    5-Fold CV Accuracy : {cv.mean()*100:.2f}% (+/- {cv.std()*100:.2f}%)")

        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)

        acc  = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec  = recall_score(y_test, y_pred, zero_division=0)
        f1   = f1_score(y_test, y_pred, zero_division=0)
        cm   = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        print(f"    Test Accuracy      : {acc*100:.2f}%")
        print(f"    Precision          : {prec*100:.2f}%")
        print(f"    Recall             : {rec*100:.2f}%")
        print(f"    F1-Score           : {f1*100:.2f}%")
        print(f"    False Alarm Rate   : {fpr*100:.2f}%")

        if f1 > best_f1:
            best_f1 = f1
            champion_name = name
            champion_model = clf
            champion_metrics = dict(acc=acc, prec=prec, rec=rec, f1=f1, fpr=fpr)

    print(f"\n{'='*55}")
    print(f"  CHAMPION: {champion_name}")
    print(f"{'='*55}")
    print(f"  Accuracy   : {champion_metrics['acc']*100:.2f}%")
    print(f"  F1-Score   : {champion_metrics['f1']*100:.2f}%")
    print(f"  False Alarms: {champion_metrics['fpr']*100:.2f}%")

    # ── Feature importance ───────────────────────────────
    print("\n--- Feature Importance (Champion) ---")
    imp = champion_model.feature_importances_
    ranked = sorted(zip(X.columns, imp), key=lambda x: x[1], reverse=True)
    print(f"{'Rank':>4}  {'Feature':<28}  {'Importance':>10}")
    print("-" * 48)
    for i, (feat, score) in enumerate(ranked, 1):
        bar = "#" * int(score * 40)
        print(f"{i:>4}  {feat:<28}  {score*100:>8.2f}%  {bar}")

    # ── Persist ──────────────────────────────────────────
    print(f"\nSaving champion model -> {model_path}")
    with open(model_path, "wb") as f:
        pickle.dump(champion_model, f)
    print("Model saved. Ready for inference.\n")


if __name__ == "__main__":
    main()