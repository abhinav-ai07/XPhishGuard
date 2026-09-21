import os
import json
import base64
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables (.env from current directory or parent directory)
load_dotenv()
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from predict import predict_url

app = Flask(__name__)
CORS(app)


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "project": "XPhishGuard AI — Explainable AI Threat Intelligence Layer",
        "api_endpoints": {
            "health_check": "GET /api/health",
            "prediction": "POST /api/predict",
            "audit_report": "GET /api/audit",
            "explanation_plots": "GET /api/explanations/<filename>"
        },
        "system_info": "29-Feature Advanced Lexical + Semantic + Payload XAI Engine",
    }), 200


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "success": True,
        "message": "XPhishGuard API Gateway is healthy and running.",
    }), 200


@app.route("/api/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "success": False,
            "error": "Invalid request payload. Content-Type must be application/json.",
        }), 400

    url = data.get("url")
    if not url:
        return jsonify({
            "success": False,
            "error": "Missing required field: 'url'.",
        }), 400

    if not isinstance(url, str):
        return jsonify({
            "success": False,
            "error": "The 'url' field must be a string.",
        }), 400

    try:
        res = predict_url(url)
        return jsonify({
            "success": True,
            "url": res["url"],
            "is_phishing": res["is_phishing"],
            "confidence_score": res["confidence_score"],
            "risk_level": res["risk_level"],
            "triggered_signals": res["triggered_signals"],
            "threat_intelligence": res["threat_intelligence"],
            "top_contributors": res["top_contributors"],
            "feature_importance": res["feature_importance"],
            "human_explanations": res["human_explanations"],
            "analyst_summary": res["analyst_summary"],
            "threat_timeline": res["threat_timeline"],
            "visualizations": res["visualizations"],
            "extracted_features": res["extracted_features"],
            "analyst_report": res["analyst_report"],
            
            # Phase 5 endpoints addition
            "brand_detection": res.get("brand_detection"),
            "attack_classification": res.get("attack_classification"),
            "risk_scorecard": res.get("risk_scorecard"),
            "recommendations": res.get("recommendations"),
            "full_analyst_report": res.get("full_analyst_report")
        }), 200
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"Internal Server Error: {exc}",
        }), 500


@app.route("/api/audit", methods=["GET"])
def get_audit_report():
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    exp_dir = os.path.join(backend_dir, "explanations")
    json_path = os.path.join(exp_dir, "model_audit_report.json")
    
    if not os.path.exists(json_path):
        return jsonify({
            "success": False,
            "error": "Audit report not found. Run advanced XAI audit script first."
        }), 404
        
    try:
        with open(json_path, "r") as f:
            audit_data = json.load(f)
            
        # Read global plots as base64
        plots = {}
        for plot_name in ["global_summary_plot.png", "feature_correlation.png"]:
            path = os.path.join(exp_dir, plot_name)
            if os.path.exists(path):
                with open(path, "rb") as img_f:
                    plots[plot_name.split(".")[0]] = base64.b64encode(img_f.read()).decode('utf-8')
                    
        return jsonify({
            "success": True,
            "report": audit_data,
            "plots": plots
        }), 200
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"Error loading audit report: {exc}"
        }), 500


@app.route("/api/explanations/<filename>", methods=["GET"])
def get_explanation_file(filename):
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    exp_dir = os.path.join(backend_dir, "explanations")
    if not os.path.exists(os.path.join(exp_dir, filename)):
        return jsonify({
            "success": False,
            "error": f"File {filename} not found."
        }), 404
    return send_from_directory(exp_dir, filename)


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found. Please use /api/health, /api/predict or /api/audit.",
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "error": "HTTP method not allowed for this endpoint.",
    }), 405


if __name__ == "__main__":
    print("Starting XPhishGuard Flask API Gateway...")
    app.run(host="0.0.0.0", port=5000, debug=True)