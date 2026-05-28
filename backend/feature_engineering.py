"""
XPhishGuard AI — Phase 1.5 Context-Aware Domain Intelligence Engine
====================================================================

Implements a 24-feature lexical + semantic suite using tldextract (Public
Suffix List) and rapidfuzz (Levenshtein).

Key upgrades over Phase 1:
- repeated_char_max REMOVED  (caused www. false positives on youtube/github)
- 6 semantic category features ADDED (streaming, AI, coding, social, etc.)
- is_institutional_tld ADDED (.edu / .gov / .ac.in / .gov.in etc.)
- Redirect param detection TIGHTENED (no longer flags v=, id=, page=)
- Brand impersonation uses 3-pass: exact segment / Levenshtein / containment
- TRUSTED_DOMAINS expanded to 100+ root names
"""

import re
import math
import tldextract
from rapidfuzz import distance as rdist

# ─────────────────────────────────────────────────────────
#  INTELLIGENCE CATALOGUES
# ─────────────────────────────────────────────────────────

TRUSTED_DOMAINS = {
    # Search
    "google", "bing", "yahoo", "duckduckgo", "baidu", "yandex", "ask",
    # AI Platforms
    "openai", "chatgpt", "claude", "gemini", "perplexity", "anthropic",
    "copilot", "midjourney", "grok", "mistral", "huggingface", "cohere",
    # Video / Streaming / Music
    "youtube", "netflix", "spotify", "twitch", "hulu", "hotstar",
    "primevideo", "vimeo", "dailymotion", "soundcloud", "appletv",
    "disneyplus", "tidal", "pandora", "crunchyroll",
    # Coding / DevOps
    "github", "gitlab", "bitbucket", "stackoverflow", "leetcode",
    "hackerrank", "codeforces", "codechef", "geeksforgeeks", "kaggle",
    "replit", "codesandbox", "vercel", "netlify", "heroku", "render",
    "digitalocean", "linode",
    # Education / Learning
    "coursera", "udemy", "edx", "pluralsight", "codecademy",
    "freecodecamp", "khanacademy", "skillshare", "duolingo", "byjus",
    "unacademy", "brilliant",
    # Productivity / SaaS
    "notion", "figma", "canva", "miro", "trello", "asana", "slack",
    "zoom", "dropbox", "box", "airtable", "clickup", "linear", "jira",
    "confluence", "monday",
    # Social Media
    "twitter", "x", "facebook", "instagram", "linkedin", "reddit",
    "discord", "telegram", "whatsapp", "pinterest", "tumblr", "quora",
    "snapchat", "tiktok", "mastodon",
    # Shopping / Finance
    "amazon", "flipkart", "shopify", "etsy", "ebay", "walmart",
    "target", "bestbuy", "stripe", "razorpay", "paypal",
    # Big Tech / Cloud
    "apple", "microsoft", "google", "aws", "azure", "cloudflare",
    "godaddy", "namecheap",
    # Reference / Media
    "wikipedia", "archive", "medium", "substack", "wordpress",
    # Educational Institutions
    "rvce", "iitb", "iitd", "iisc", "bits", "vit", "manipal",
    "mit", "stanford", "harvard", "berkeley", "caltech",
    "oxford", "cambridge", "yale", "princeton", "columbia",
}

# Semantic category sets (root domain only, no TLD)
SEARCH_ENGINES   = {"google", "bing", "yahoo", "duckduckgo", "baidu", "yandex", "ask"}
AI_PLATFORMS     = {"openai", "chatgpt", "claude", "gemini", "perplexity",
                    "anthropic", "copilot", "midjourney", "grok", "mistral",
                    "huggingface", "cohere"}
STREAMING        = {"youtube", "netflix", "spotify", "twitch", "hulu", "hotstar",
                    "primevideo", "vimeo", "dailymotion", "soundcloud", "appletv",
                    "disneyplus", "tidal", "pandora", "crunchyroll"}
CODING           = {"github", "gitlab", "bitbucket", "stackoverflow", "leetcode",
                    "hackerrank", "codeforces", "codechef", "geeksforgeeks", "kaggle",
                    "replit", "codesandbox", "vercel", "netlify", "heroku", "render"}
EDUCATIONAL      = {"coursera", "udemy", "edx", "pluralsight", "codecademy",
                    "freecodecamp", "khanacademy", "skillshare", "duolingo",
                    "byjus", "unacademy", "brilliant", "wikipedia", "archive"}
SOCIAL           = {"twitter", "x", "facebook", "instagram", "linkedin", "reddit",
                    "discord", "telegram", "whatsapp", "pinterest", "quora",
                    "snapchat", "tiktok", "mastodon"}

# Institutional TLD suffixes — .edu / .gov families
# tldextract returns the full suffix (e.g., "edu.in" for rvce.edu.in)
INSTITUTIONAL_TLDS = {
    "edu", "gov", "mil", "int",
    "ac.in", "edu.in", "gov.in", "nic.in", "res.in",
    "ac.uk", "gov.uk", "edu.au", "gov.au",
    "ac.nz", "edu.cn", "edu.sg",
}

# High-risk cheap TLDs popular with phishing campaigns
RISKY_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "club", "top", "vip",
    "win", "bid", "stream", "date", "download", "online", "icu",
    "site", "info", "cc", "work", "click",
}

# URL shorteners
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "ow.ly", "bit.do", "mcaf.ee", "rebrand.ly",
    "shorturl.at",
}

# Social-engineering phishing keywords
SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "update", "signin", "account", "billing",
    "security", "support", "recovery", "validation", "confirm", "bonus",
    "free", "giftcard", "alert", "webscr", "cmd", "reset-password",
    "credential", "authenticate", "unlock", "suspend",
}

# Scam / adult / malware keywords
SCAM_KEYWORDS = {
    "free-crypto", "bitcoin-gift", "adult-dating", "porn", "casino",
    "gamble", "crack-serial", "download-zip", "claim-bonus", "lottery",
    "cash-prize", "rich-quick", "viagra", "levitra", "webcam-leak",
    "earn-daily", "airdrop-claim",
}

# Redirect-abuse param names (tightened — no longer flags v=, id=, page=)
REDIRECT_PARAMS = {
    "redirect", "redir", "goto", "forward", "return_to",
    "bounce", "out", "external_url",
}

# Brand catalogue for impersonation checks
TARGET_BRANDS = list(TRUSTED_DOMAINS)

# IPv4 regex
_IPV4_RE = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')


# ─────────────────────────────────────────────────────────
#  UTILITY
# ─────────────────────────────────────────────────────────

def _entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# ─────────────────────────────────────────────────────────
#  CORE FEATURE EXTRACTOR
# ─────────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Returns a 24-dimensional feature dictionary from a raw URL string.
    """
    url = url.strip()
    url_lower = url.lower()

    # ── Basic structural counts ──────────────────────────
    url_length   = len(url)
    dot_count    = url.count('.')
    hyphen_count = url.count('-')
    has_https    = 1 if url_lower.startswith('https://') else 0
    has_at_symbol = 1 if '@' in url else 0

    # ── tldextract domain decomposition ─────────────────
    try:
        ext = tldextract.extract(url)
        root_domain = ext.domain.lower()          # e.g. 'youtube'
        tld_suffix  = ext.suffix.lower()          # e.g. 'com' / 'co.uk' / 'edu.in'
        subdomain   = ext.subdomain.lower()       # e.g. 'www' / 'docs'
        reg_host    = f"{root_domain}.{tld_suffix}" if tld_suffix else root_domain
    except Exception:
        root_domain = subdomain = tld_suffix = reg_host = ""

    # ── IP address check ────────────────────────────────
    is_ip_address = 1 if _IPV4_RE.match(root_domain) else 0

    # ── Institutional TLD ────────────────────────────────
    # Trusts .edu / .gov / .ac.in / .gov.in etc.
    # Real enterprise firewalls treat these differently — institutional
    # registrars have strict vetting; free phishing kits can't get .gov
    is_institutional_tld = 1 if tld_suffix in INSTITUTIONAL_TLDS else 0

    # ── Risky TLD ────────────────────────────────────────
    tld_top = tld_suffix.split('.')[0] if tld_suffix else ""
    is_risky_tld = 1 if (tld_top in RISKY_TLDS or tld_suffix in RISKY_TLDS) else 0

    # ── Trusted domain ───────────────────────────────────
    # Anchored to the registered root so subdomains of trusted hosts
    # (docs.google.com, api.github.com) are also trusted.
    is_trusted_domain = 1 if root_domain in TRUSTED_DOMAINS else 0

    # ── Semantic category features ───────────────────────
    is_search_engine      = 1 if root_domain in SEARCH_ENGINES  else 0
    is_ai_platform        = 1 if root_domain in AI_PLATFORMS    else 0
    is_streaming_platform = 1 if root_domain in STREAMING       else 0
    is_coding_platform    = 1 if root_domain in CODING          else 0
    is_educational_platform = 1 if root_domain in EDUCATIONAL   else 0
    is_social_platform    = 1 if root_domain in SOCIAL          else 0

    # ── Brand impersonation (3-pass, skipped for trusted roots) ──
    brand_impersonation = 0
    if root_domain and not is_trusted_domain:
        # Segments of hyphenated compound names (e.g. paypal-verify-secure)
        parts = [p for p in root_domain.split('-') if len(p) >= 4]

        # Pass A: exact segment matches a known brand
        for p in parts:
            for b in TARGET_BRANDS:
                if p == b:
                    brand_impersonation = 1
                    break
            if brand_impersonation:
                break

        # Pass B: Levenshtein ≤ 2 on each segment (catches netfliix, gooogle)
        if not brand_impersonation:
            for p in parts:
                for b in TARGET_BRANDS:
                    if abs(len(p) - len(b)) <= 2:
                        if 0 < rdist.Levenshtein.distance(p, b) <= 2:
                            brand_impersonation = 1
                            break
                if brand_impersonation:
                    break

        # Pass C: brand string embedded in full root domain
        if not brand_impersonation:
            for b in TARGET_BRANDS:
                if len(b) >= 5 and b in root_domain and root_domain != b:
                    brand_impersonation = 1
                    break

    # ── Shannon entropy of registered domain ─────────────
    domain_entropy = _entropy(root_domain)

    # ── Digit ratio in registered domain ─────────────────
    digit_ratio = (
        sum(1 for c in root_domain if c.isdigit()) / len(root_domain)
        if root_domain else 0.0
    )

    # ── Subdomain depth ───────────────────────────────────
    subdomain_count = len(subdomain.split('.')) if subdomain else 0

    # ── Token count from full URL ─────────────────────────
    tokens = [t for t in re.split(r'[^a-zA-Z0-9]', url_lower) if t]
    token_count = len(tokens)

    # ── Social-engineering keyword density ───────────────
    kw_hits = sum(1 for t in tokens if t in SUSPICIOUS_KEYWORDS)
    keyword_density = kw_hits / token_count if token_count else 0.0

    # ── URL shortener ────────────────────────────────────
    is_shortened = 1 if reg_host in SHORTENERS else 0

    # ── Redirect param abuse (tightened keyword list) ────
    has_redirect_params = 0
    if '?' in url_lower:
        query = url_lower.split('?', 1)[1]
        for pair in query.split('&'):
            key = pair.split('=')[0]
            if key in REDIRECT_PARAMS:
                has_redirect_params = 1
                break

    # ── Scam / adult / malware keywords ─────────────────
    has_scam_keywords = 1 if any(k in url_lower for k in SCAM_KEYWORDS) else 0

    return {
        "url_length":             url_length,
        "dot_count":              dot_count,
        "hyphen_count":           hyphen_count,
        "has_https":              has_https,
        "has_at_symbol":          has_at_symbol,
        "is_ip_address":          is_ip_address,
        "is_risky_tld":           is_risky_tld,
        "brand_impersonation":    brand_impersonation,
        "domain_entropy":         domain_entropy,
        "digit_ratio":            digit_ratio,
        "subdomain_count":        subdomain_count,
        "token_count":            token_count,
        "keyword_density":        keyword_density,
        "is_shortened":           is_shortened,
        "has_redirect_params":    has_redirect_params,
        "has_scam_keywords":      has_scam_keywords,
        "is_trusted_domain":      is_trusted_domain,
        "is_institutional_tld":   is_institutional_tld,
        "is_search_engine":       is_search_engine,
        "is_ai_platform":         is_ai_platform,
        "is_streaming_platform":  is_streaming_platform,
        "is_coding_platform":     is_coding_platform,
        "is_educational_platform":is_educational_platform,
        "is_social_platform":     is_social_platform,
    }


def get_feature_list(url: str) -> list:
    """Ordered list matching the training matrix column order (24 features)."""
    f = extract_features(url)
    return [
        f["url_length"],
        f["dot_count"],
        f["hyphen_count"],
        f["has_https"],
        f["has_at_symbol"],
        f["is_ip_address"],
        f["is_risky_tld"],
        f["brand_impersonation"],
        f["domain_entropy"],
        f["digit_ratio"],
        f["subdomain_count"],
        f["token_count"],
        f["keyword_density"],
        f["is_shortened"],
        f["has_redirect_params"],
        f["has_scam_keywords"],
        f["is_trusted_domain"],
        f["is_institutional_tld"],
        f["is_search_engine"],
        f["is_ai_platform"],
        f["is_streaming_platform"],
        f["is_coding_platform"],
        f["is_educational_platform"],
        f["is_social_platform"],
    ]


# ─────────────────────────────────────────────────────────
#  SELF-TEST
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import tldextract as _tld
    tests = [
        ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLxx", "SAFE"),
        ("https://github.com/torvalds/linux/issues/1234",           "SAFE"),
        ("https://chatgpt.com/share/abc123",                        "SAFE"),
        ("http://www.rvce.edu.in/admissions",                       "SAFE"),
        ("https://leetcode.com/problems/two-sum/",                  "SAFE"),
        ("https://youtube-security-alert.xyz/verify",               "PHISHING"),
        ("https://netfliix-login-auth.net/signin",                  "PHISHING"),
        ("https://paypal-account-verification-alert.com/verify",    "PHISHING"),
        ("https://chatgpt-premium-free.xyz/upgrade",                "PHISHING"),
    ]
    print("\n--- Phase 1.5 Feature Engineering Self-Test ---")
    for url, expected in tests:
        f = extract_features(url)
        ext = _tld.extract(url)
        print(f"\nURL     : {url[:70]}")
        print(f"Expected: {expected}")
        print(f"  root={ext.domain!r:20} trusted={f['is_trusted_domain']}  "
              f"institutional={f['is_institutional_tld']}  "
              f"brand_spoof={f['brand_impersonation']}  "
              f"risky_tld={f['is_risky_tld']}  "
              f"entropy={f['domain_entropy']:.2f}")