"""
XPhishGuard AI — Phase 1.6 Obfuscation & Payload Intelligence Engine
=====================================================================

Implements a 29-feature lexical + semantic + structural suite.

Phase 1.6 Upgrades:
- has_malformed_chars: Detects illegal/suspicious payload symbols (!}{][, etc.)
- special_char_ratio: Density of non-alphanumeric characters
- query_entropy: Shannon entropy of the URL query string
- has_script_payload: XSS, javascript:, <script>, eval(), document.cookie
- has_homoglyph_spoof: Visual lookalikes (y0utube), Cyrillic spoofing
"""

import re
import math
import urllib.parse
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
    # Video / Streaming
    "youtube", "netflix", "spotify", "twitch", "hulu", "hotstar",
    "primevideo", "vimeo", "dailymotion", "soundcloud", "appletv", "disneyplus",
    # Coding / DevOps
    "github", "gitlab", "bitbucket", "stackoverflow", "leetcode",
    "hackerrank", "codeforces", "codechef", "geeksforgeeks", "kaggle",
    "replit", "codesandbox", "vercel", "netlify", "heroku", "render",
    # Education
    "coursera", "udemy", "edx", "pluralsight", "codecademy", "freecodecamp",
    "khanacademy", "byjus", "unacademy",
    # Productivity
    "notion", "figma", "canva", "miro", "trello", "asana", "slack", "zoom",
    "dropbox", "box", "airtable", "jira", "confluence",
    # Social Media
    "twitter", "x", "facebook", "instagram", "linkedin", "reddit",
    "discord", "telegram", "whatsapp", "pinterest", "quora", "tiktok", "mastodon",
    # Shopping / Finance
    "amazon", "flipkart", "shopify", "etsy", "ebay", "walmart", "target",
    "stripe", "razorpay", "paypal", "chase", "wellsfargo", "citibank",
    # Big Tech / Cloud
    "apple", "microsoft", "aws", "azure", "cloudflare", "godaddy", "namecheap",
    # Reference
    "wikipedia", "archive", "medium", "substack", "wordpress",
    # Institutions
    "rvce", "iitb", "iitd", "iisc", "bits", "vit", "manipal", "mit", "stanford", "harvard",
}

SEARCH_ENGINES   = {"google", "bing", "yahoo", "duckduckgo", "baidu", "yandex", "ask"}
AI_PLATFORMS     = {"openai", "chatgpt", "claude", "gemini", "perplexity", "anthropic", "copilot", "huggingface"}
STREAMING        = {"youtube", "netflix", "spotify", "twitch", "hulu", "hotstar", "primevideo"}
CODING           = {"github", "gitlab", "bitbucket", "stackoverflow", "leetcode", "hackerrank", "kaggle"}
EDUCATIONAL      = {"coursera", "udemy", "edx", "pluralsight", "codecademy", "khanacademy", "wikipedia"}
SOCIAL           = {"twitter", "x", "facebook", "instagram", "linkedin", "reddit", "discord", "tiktok"}

INSTITUTIONAL_TLDS = {
    "edu", "gov", "mil", "int", "ac.in", "edu.in", "gov.in", "nic.in", "res.in",
    "ac.uk", "gov.uk", "edu.au", "gov.au", "edu.cn", "edu.sg",
}

RISKY_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "club", "top", "vip", "win", "bid", 
    "stream", "date", "download", "online", "icu", "site", "info", "cc", "work", "click",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "adf.ly", 
    "ow.ly", "bit.do", "mcaf.ee", "rebrand.ly", "shorturl.at",
}

SUSPICIOUS_KEYWORDS = {
    "login", "verify", "secure", "update", "signin", "account", "billing",
    "security", "support", "recovery", "validation", "confirm", "bonus",
    "free", "giftcard", "alert", "webscr", "cmd", "reset-password",
    "credential", "authenticate", "unlock", "suspend",
}

SCAM_KEYWORDS = {
    "free-crypto", "bitcoin-gift", "adult-dating", "porn", "casino",
    "gamble", "crack-serial", "download-zip", "claim-bonus", "lottery",
    "cash-prize", "rich-quick", "viagra", "levitra", "webcam-leak", "airdrop-claim",
}

REDIRECT_PARAMS = {"redirect", "redir", "goto", "forward", "return_to", "bounce", "out", "external_url"}

TARGET_BRANDS = list(TRUSTED_DOMAINS)
_IPV4_RE = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

# ─────────────────────────────────────────────────────────
#  PHASE 1.6 REGEX & ANALYSIS
# ─────────────────────────────────────────────────────────

# Script/XSS Injection Patterns
SCRIPT_PAYLOAD_RE = re.compile(
    r'(<script>|javascript:|alert\(|eval\(|document\.cookie|onerror=|onload=|%3Cscript%3E|%3C%2Fscript%3E|onmouseover=)',
    re.IGNORECASE
)

# Malformed symbols (abuse of delimiters)
MALFORMED_CHARS_RE = re.compile(r'[!}\{\]\[\|\^<>`\\]')

# Cyrillic/Non-Latin blocks commonly used for visual spoofing
# Excludes safe Latin, standard punctuation, and Asian scripts if expected
HOMOGLYPH_RE = re.compile(r'[\u0400-\u04FF\u0500-\u052F\u1D00-\u1D7F]') 


def _entropy(text: str) -> float:
    """Shannon entropy of a string."""
    if not text: return 0.0
    freq = {}
    for c in text: freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


# ─────────────────────────────────────────────────────────
#  CORE FEATURE EXTRACTOR
# ─────────────────────────────────────────────────────────

def extract_features(url: str) -> dict:
    # 1. URL SANITIZATION & NORMALIZATION
    # Decode URL-encoded characters (%20, %3C, etc) so attackers can't hide payloads
    unquoted_url = urllib.parse.unquote(url.strip())
    url_lower = unquoted_url.lower()

    # ── Basic structural counts ──────────────────────────
    url_length   = len(url_lower)
    dot_count    = url_lower.count('.')
    hyphen_count = url_lower.count('-')
    has_https    = 1 if url_lower.startswith('https://') else 0
    has_at_symbol = 1 if '@' in url_lower else 0

    # ── tldextract domain decomposition ─────────────────
    try:
        ext = tldextract.extract(url_lower)
        root_domain = ext.domain          # e.g. 'youtube'
        tld_suffix  = ext.suffix          # e.g. 'com'
        subdomain   = ext.subdomain       # e.g. 'www'
        reg_host    = f"{root_domain}.{tld_suffix}" if tld_suffix else root_domain
    except Exception:
        root_domain = subdomain = tld_suffix = reg_host = ""

    # ── Phase 1.6 Payload & Obfuscation Analysis ─────────
    
    # query extraction
    query = url_lower.split('?', 1)[1] if '?' in url_lower else ""

    # Malformed / Illegal Characters
    has_malformed_chars = 1 if MALFORMED_CHARS_RE.search(unquoted_url) else 0

    # Script Injection
    has_script_payload = 1 if SCRIPT_PAYLOAD_RE.search(unquoted_url) else 0

    # Query Entropy (High entropy = encrypted/encoded obfuscation)
    query_entropy = _entropy(query)

    # Special Character Ratio (High density = obfuscation)
    alnum_count = sum(1 for c in unquoted_url if c.isalnum())
    special_char_count = url_length - alnum_count
    special_char_ratio = special_char_count / url_length if url_length > 0 else 0.0

    # Homoglyph / Visual Spoofing
    has_homoglyph_spoof = 0
    if HOMOGLYPH_RE.search(root_domain):
        has_homoglyph_spoof = 1
    # Simple ASCII lookalikes in root domain (e.g. y0utube, g00gle)
    # Check if a known brand is matched when 0 is replaced by o
    if root_domain and not has_homoglyph_spoof:
        sanitized_root = root_domain.replace('0', 'o').replace('1', 'l')
        for b in TARGET_BRANDS:
            if sanitized_root == b and root_domain != b:
                has_homoglyph_spoof = 1
                break

    # ── Domain Trust & Rep ───────────────────────────────
    is_ip_address = 1 if _IPV4_RE.match(root_domain) else 0
    is_institutional_tld = 1 if tld_suffix in INSTITUTIONAL_TLDS else 0
    tld_top = tld_suffix.split('.')[0] if tld_suffix else ""
    is_risky_tld = 1 if (tld_top in RISKY_TLDS or tld_suffix in RISKY_TLDS) else 0
    is_trusted_domain = 1 if root_domain in TRUSTED_DOMAINS else 0

    # ── Semantic Categories ──────────────────────────────
    is_search_engine      = 1 if root_domain in SEARCH_ENGINES  else 0
    is_ai_platform        = 1 if root_domain in AI_PLATFORMS    else 0
    is_streaming_platform = 1 if root_domain in STREAMING       else 0
    is_coding_platform    = 1 if root_domain in CODING          else 0
    is_educational_platform = 1 if root_domain in EDUCATIONAL   else 0
    is_social_platform    = 1 if root_domain in SOCIAL          else 0

    # ── Brand Impersonation ──────────────────────────────
    brand_impersonation = 0
    if root_domain and not is_trusted_domain:
        parts = [p for p in root_domain.split('-') if len(p) >= 4]
        for p in parts:
            if p in TARGET_BRANDS:
                brand_impersonation = 1; break
        if not brand_impersonation:
            for p in parts:
                for b in TARGET_BRANDS:
                    if abs(len(p) - len(b)) <= 2:
                        if 0 < rdist.Levenshtein.distance(p, b) <= 2:
                            brand_impersonation = 1; break
                if brand_impersonation: break
        if not brand_impersonation:
            for b in TARGET_BRANDS:
                if len(b) >= 5 and b in root_domain and root_domain != b:
                    brand_impersonation = 1; break

    # ── Other Metrics ────────────────────────────────────
    domain_entropy = _entropy(root_domain)
    digit_ratio = sum(1 for c in root_domain if c.isdigit()) / len(root_domain) if root_domain else 0.0
    subdomain_count = len(subdomain.split('.')) if subdomain else 0
    
    tokens = [t for t in re.split(r'[^a-z0-9]', url_lower) if t]
    token_count = len(tokens)
    kw_hits = sum(1 for t in tokens if t in SUSPICIOUS_KEYWORDS)
    keyword_density = kw_hits / token_count if token_count else 0.0

    is_shortened = 1 if reg_host in SHORTENERS else 0

    has_redirect_params = 0
    if query:
        for pair in query.split('&'):
            key = pair.split('=')[0]
            if key in REDIRECT_PARAMS:
                has_redirect_params = 1; break

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
        # Phase 1.6
        "has_malformed_chars":    has_malformed_chars,
        "special_char_ratio":     special_char_ratio,
        "query_entropy":          query_entropy,
        "has_script_payload":     has_script_payload,
        "has_homoglyph_spoof":    has_homoglyph_spoof,
    }

def get_feature_list(url: str) -> list:
    f = extract_features(url)
    return [
        f["url_length"], f["dot_count"], f["hyphen_count"], f["has_https"],
        f["has_at_symbol"], f["is_ip_address"], f["is_risky_tld"], f["brand_impersonation"],
        f["domain_entropy"], f["digit_ratio"], f["subdomain_count"], f["token_count"],
        f["keyword_density"], f["is_shortened"], f["has_redirect_params"],
        f["has_scam_keywords"], f["is_trusted_domain"], f["is_institutional_tld"],
        f["is_search_engine"], f["is_ai_platform"], f["is_streaming_platform"],
        f["is_coding_platform"], f["is_educational_platform"], f["is_social_platform"],
        f["has_malformed_chars"], f["special_char_ratio"], f["query_entropy"],
        f["has_script_payload"], f["has_homoglyph_spoof"]
    ]