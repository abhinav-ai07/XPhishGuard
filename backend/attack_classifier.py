def classify_attack(url: str, extracted_features: dict, is_phishing: bool) -> dict:
    classes = {
        "Credential Harvesting": 0.0,
        "Banking Phishing": 0.0,
        "Fake Login": 0.0,
        "Malware Delivery": 0.0,
        "Social Engineering": 0.0,
    }
    
    if not is_phishing:
        return {
            "primary_attack_type": "None",
            "probabilities": classes
        }
        
    url_lower = url.lower()
    has_evidence = False
    
    # Require strict evidence
    if "login" in url_lower or "signin" in url_lower or "auth" in url_lower or extracted_features.get("has_scam_keywords"):
        classes["Fake Login"] = 0.85
        classes["Credential Harvesting"] = 0.90
        has_evidence = True
        
    if "bank" in url_lower or "paypal" in url_lower or "secure" in url_lower or "wallet" in url_lower:
        classes["Banking Phishing"] = 0.88
        has_evidence = True
        
    if "download" in url_lower or "exe" in url_lower or "apk" in url_lower or extracted_features.get("has_script_payload"):
        classes["Malware Delivery"] = 0.95
        has_evidence = True
        
    if "free" in url_lower or "gift" in url_lower or "win" in url_lower or "bonus" in url_lower:
        classes["Social Engineering"] = 0.75
        has_evidence = True
        
    if extracted_features.get("brand_impersonation") == 1:
        classes["Credential Harvesting"] = max(classes["Credential Harvesting"], 0.85)
        has_evidence = True

    if not has_evidence:
        return {
            "primary_attack_type": "None",
            "probabilities": classes
        }
        
    top_class = max(classes, key=classes.get)
    
    return {
        "primary_attack_type": top_class,
        "probabilities": classes
    }
