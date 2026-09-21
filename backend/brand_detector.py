from feature_engineering import TARGET_BRANDS

def detect_brand_impersonation(url: str, extracted_features: dict) -> dict:
    # Do NOT invent brands. Only flag if our feature engine explicitly caught it
    if extracted_features.get("brand_impersonation") == 1:
        url_lower = url.lower()
        import tldextract
        from rapidfuzz import distance as rdist
        
        ext = tldextract.extract(url_lower)
        root = ext.domain
        
        likely_target = None
        
        # Try finding the exact brand in the domain parts
        parts = [p for p in root.split('-') if len(p) >= 4]
        for p in parts:
            if p in TARGET_BRANDS:
                likely_target = p
                break
                
        # Try finding a fuzzy match
        if not likely_target:
            for p in parts:
                for b in TARGET_BRANDS:
                    if abs(len(p) - len(b)) <= 2:
                        if 0 < rdist.Levenshtein.distance(p, b) <= 2:
                            likely_target = b
                            break
                if likely_target: break
                
        # Substring match
        if not likely_target:
            for b in TARGET_BRANDS:
                if len(b) >= 5 and b in root and root != b:
                    likely_target = b
                    break
                    
        # Homoglyph spoofing
        if not likely_target and extracted_features.get("has_homoglyph_spoof") == 1:
            sanitized = root.replace('0', 'o').replace('1', 'l')
            if sanitized in TARGET_BRANDS:
                likely_target = sanitized
                
        if likely_target:
            return {
                "is_impersonation": True,
                "impersonation_detected": True,
                "likely_target_brand": likely_target.capitalize(),
                "confidence": 0.90,
                "matched_keywords": [likely_target],
                "visual_similarity_score": 0.85
            }
            
    return {
        "is_impersonation": False,
        "impersonation_detected": False,
        "likely_target_brand": None,
        "confidence": 0.0,
        "matched_keywords": [],
        "visual_similarity_score": 0.0
    }
