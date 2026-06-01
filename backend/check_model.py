import pickle
import os

backend_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(backend_dir, "models", "phishing_model.pkl")

if os.path.exists(model_path):
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    print("Model loaded successfully!")
    print("Model class:", type(model))
    if hasattr(model, "feature_importances_"):
        print("Model has feature importances.")
else:
    print("Model file does not exist.")
