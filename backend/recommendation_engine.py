def get_recommendations(user_type: str, is_phishing: bool, attack_type: str) -> list:
    if not is_phishing:
        return ["Continue browsing safely.", "Keep your software updated."]
        
    base_recs = ["Do not click any links or download any files from this site.", "Close the browser tab immediately."]
    
    if user_type == "Student":
        base_recs.append("Report this to your university IT helpdesk if it's school-related.")
    elif user_type == "Employee":
        base_recs.append("Forward this URL to your corporate security team.")
    elif user_type == "Developer":
        base_recs.append("Analyze the payload in a sandboxed environment if necessary.")
    elif user_type == "Business Owner":
        base_recs.append("Warn your employees about this active phishing campaign.")
    elif user_type == "Bank Customer":
        base_recs.append("If you entered credentials, call your bank immediately to freeze your account.")
    elif user_type == "Senior Citizen":
        base_recs.append("Ask a trusted family member to help you secure your device.")
        
    if "Credential" in attack_type:
        base_recs.append("Enable Multi-Factor Authentication (MFA) on your critical accounts.")
        
    return base_recs
