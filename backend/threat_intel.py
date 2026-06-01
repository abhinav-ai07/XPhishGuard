import sys
import os

# Ensure backend directory is in path
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.append(backend_dir)

from services.virustotal import query_virustotal
from services.phishtank import query_phishtank
from services.openphish import query_openphish
from services.urlhaus import query_urlhaus

def get_threat_intelligence(url: str) -> dict:
    """
    Queries VirusTotal, PhishTank, OpenPhish, and URLHaus,
    aggregates results, and returns threat intel data.
    """
    vt_detections = query_virustotal(url)
    pt_match = query_phishtank(url)
    op_match = query_openphish(url)
    uh_match = query_urlhaus(url)
    
    return {
        "virustotal": {
            "detections": vt_detections
        },
        "phishtank": pt_match,
        "openphish": op_match,
        "urlhaus": uh_match
    }

def calculate_threat_intel_boost(ti_data: dict) -> tuple[float, list[tuple[str, float, str]]]:
    """
    Calculates threat intelligence score boost based on triggers:
    - PhishTank match: +40% (+0.40)
    - OpenPhish match: +40% (+0.40)
    - VirusTotal > 20 detections: +30% (+0.30)
    - URLHaus match: +50% (+0.50)
    
    Returns the total boost, and a list of triggered intelligence events
    with (feature_name, score_boost, signal_message) for SHAP and explanations.
    """
    boost = 0.0
    triggers = []
    
    if ti_data.get("phishtank"):
        boost += 0.40
        triggers.append(("phishtank_match", 0.40, "PhishTank Threat Feed Match"))
        
    if ti_data.get("openphish"):
        boost += 0.40
        triggers.append(("openphish_match", 0.40, "OpenPhish Threat Feed Match"))
        
    if ti_data.get("virustotal", {}).get("detections", 0) > 20:
        boost += 0.30
        triggers.append(("virustotal_detections", 0.30, f"VirusTotal Alert ({ti_data['virustotal']['detections']} detections)"))
        
    if ti_data.get("urlhaus"):
        boost += 0.50
        triggers.append(("urlhaus_match", 0.50, "URLHaus Threat Feed Match"))
        
    return boost, triggers
