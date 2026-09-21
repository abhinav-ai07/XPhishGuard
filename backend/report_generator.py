import datetime

def generate_analyst_report(
    url: str,
    is_phishing: bool,
    confidence: float,
    attack_data: dict,
    brand_data: dict,
    risk_scorecard: dict,
    recommendations: list
) -> dict:

    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    # -----------------------------
    # Final Risk Score
    # -----------------------------
    risk = risk_scorecard.get("overall_risk", 0)

    # -----------------------------
    # Threat Severity
    # -----------------------------
    if risk >= 90:
        severity = "CRITICAL"
    elif risk >= 71:
        severity = "HIGH"
    elif risk >= 41:
        severity = "MEDIUM"
    elif risk >= 16:
        severity = "LOW"
    else:
        severity = "SAFE"

    # -----------------------------
    # Business Impact
    # -----------------------------
    if risk >= 90:
        business_impact = (
            "Critical phishing threat detected. High probability of credential theft and account compromise."
        )
    elif risk >= 71:
        business_impact = (
            "High-risk website. User interaction is strongly discouraged."
        )
    elif risk >= 41:
        business_impact = (
            "Suspicious indicators detected. Verify the website before proceeding."
        )
    elif risk >= 16:
        business_impact = (
            "Low-risk indicators present. Continue with caution."
        )
    else:
        business_impact = (
            "No significant malicious indicators detected."
        )

    report = {
        "report_id": f"REP-{int(datetime.datetime.now().timestamp())}",
        "timestamp": timestamp,
        "target_url": url,
        "executive_summary": (
            f"The analyzed URL has been classified as "
            f"{'PHISHING' if is_phishing else 'SAFE'} "
            f"with a confidence of {confidence*100:.1f}%."
        ),
        "threat_assessment": {
            "severity": severity,
            "attack_type": attack_data.get("primary_attack_type", "None"),
            "target_brand": brand_data.get("likely_target_brand", "None")
        },
        "mitre_attack_mapping": [],
        "business_impact": business_impact,
        "risk_rating": risk_scorecard,
        "recommendations": recommendations,
        "incident_response_steps": (
            [
                "Block the URL at the secure web gateway.",
                "Search enterprise logs for users who accessed this URL.",
                "Reset credentials for affected users.",
                "Notify the security operations team.",
                "Monitor for further phishing activity."
            ]
            if is_phishing
            else []
        )
    }

    # MITRE ATT&CK Mapping
    attack_type = attack_data.get("primary_attack_type", "")

    if "Credential Harvesting" in attack_type:
        report["mitre_attack_mapping"].append({
            "id": "T1056",
            "name": "Input Capture"
        })

    if "Fake Login" in attack_type:
        report["mitre_attack_mapping"].append({
            "id": "T1185",
            "name": "Browser Session Hijacking"
        })

    if "Malware Delivery" in attack_type:
        report["mitre_attack_mapping"].append({
            "id": "T1204.001",
            "name": "User Execution: Malicious Link"
        })

    return report