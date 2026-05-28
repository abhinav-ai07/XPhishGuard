from flask import Flask, jsonify, request
from flask_cors import CORS

from predict import predict_url

app = Flask(__name__)
CORS(app)


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "project": "XPhishGuard AI - AI-Powered Phishing URL Detection System",
        "api_endpoints": {
            "health_check": "GET /api/health",
            "prediction": "POST /api/predict",
        },
        "system_info": "18-Feature Advanced Engineering + Champion Classifier",
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
        prediction_result = predict_url(url)
        return jsonify({
            "success": True,
            "url": prediction_result["url"],
            "is_phishing": prediction_result["is_phishing"],
            "confidence_score": prediction_result["confidence"],
            "phishing_probability": prediction_result.get("phishing_probability"),
            "extracted_features": prediction_result["features"],
            "rule_applied": prediction_result.get("rule_applied"),
        }), 200
    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"Internal Server Error: {exc}",
        }), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": "Endpoint not found. Please use /api/health or /api/predict.",
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