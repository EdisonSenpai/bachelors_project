from flask import Flask, request, jsonify
import joblib
import pandas as pd
import shap
from joblib import load
from flask_cors import CORS
import numpy as np
import matplotlib.pyplot as plt
import base64
import io
from io import BytesIO
import pandas as pd
import os

app = Flask(__name__)
CORS(app, supports_credentials=True)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "classifier_model.joblib")
LABEL_ENNCODER_PATH = os.path.join(os.path.dirname(__file__), "model", "label_encoder.joblib")
PROTO_ENCODER_PATH = os.path.join(os.path.dirname(__file__), "model", "proto_encoder.joblib")
SIG_ENCODER_PATH = os.path.join(os.path.dirname(__file__), "model", "sig_encoder.joblib")

# Incarca modelul
model = joblib.load(MODEL_PATH)
label_encoder = joblib.load(LABEL_ENNCODER_PATH)
proto_encoder = joblib.load(PROTO_ENCODER_PATH)
sig_encoder = joblib.load(SIG_ENCODER_PATH)

def predict_label(alert):
    try:
        proto = alert.get("proto", "-")
        signature = alert.get("signature", "-")

        proto_val = proto_encoder.transform([proto])[0] if proto in proto_encoder.classes_ else -1
        sig_val = sig_encoder.transform([signature])[0] if signature in sig_encoder.classes_ else -1

        if proto_val == -1 or sig_val == -1:
            return classify_alert(signature)

        X_new = pd.DataFrame([[proto_val, sig_val]], columns=['proto_encoded', 'signature_encoded'])
        prediction = model.predict(X_new)[0]

        return label_encoder.inverse_transform([prediction])[0]
    except Exception as e:
        print("Eroare la predictie AI:", e)
        return classify_alert(alert.get("signature", "-"))

def classify_alert(signature):
    signature = signature.lower()
    if 'scan' in signature:
        return 'scan'
    elif 'trojan' in signature or 'exploit' in signature:
        return 'malicious'
    elif 'torrent' in signature:
        return 'suspicious'
    elif 'attempt' in signature or 'attack' in signature:
        return 'suspicious'
    else:
        return 'normal'

@app.route("/predict_label", methods=["POST"])
def predict_label_route():
    try:
        data = request.json
        label = predict_label(data)
        return jsonify({"predicted_label": label})
    except Exception as e:
        return jsonify({"predicted_label": "necunoscut", "error": str(e)}), 500

@app.route('/explain_alert', methods=['POST'])
def explain_alert():
    try:
        data = request.json
        proto = data.get("proto", "-")
        signature = data.get("signature", "-")

        proto_val = proto_encoder.transform([proto])[0] if proto in proto_encoder.classes_ else -1
        sig_val = sig_encoder.transform([signature])[0] if signature in sig_encoder.classes_ else -1

        if proto_val == -1 or sig_val == -1:
            return jsonify({
                "error": "Valori necunoscute pentru proto sau signature",
                "proto": proto,
                "signature": signature
            }), 400

        input_df = pd.DataFrame([[proto_val, sig_val]], columns=["proto_encoded", "signature_encoded"])
        prediction = model.predict(input_df)[0]
        predicted_label = label_encoder.inverse_transform([prediction])[0]

        importances = model.feature_importances_
        explanation = {
            "predicted_label": predicted_label,
            "features": {
                "proto_encoded": {
                    "value": int(proto_val),
                    "importance": float(importances[0])
                },
                "signature_encoded": {
                    "value": int(sig_val),
                    "importance": float(importances[1])
                }
            }
        }

        return jsonify(explanation)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/shap_explain", methods=["POST"])
def shap_explain():
    try:
        data = request.json
        df = pd.DataFrame([data])

        proto_val = data.get("proto_encoded")
        sig_val = data.get("signature_encoded")

        #proto_decoded = proto_encoder.inverse_transform([proto_val])[0] if proto_val is not None else "necunoscut"
        #sig_decoded = sig_encoder.inverse_transform([sig_val])[0] if sig_val is not None else "necunoscut"

        print("===> DEBUG SHAP FINAL")
        print("df.columns:", df.columns.tolist())
        print("df.shape:", df.shape)
        print("df types:", df.dtypes)
        print("df head:\n", df.head())

        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(df)

        if isinstance(shap_values, list):
            shap_vals = shap_values[0][0]  # prima observatie
        else:
            shap_vals = shap_values[0]  # deja 2D

        explanation = []
        for i, col in enumerate(df.columns):
            val = shap_vals[i]
            if isinstance(val, (np.ndarray, list)):
                val = float(np.array(val).flatten()[0])

            raw_value = df.iloc[0][col]
            if isinstance(raw_value, (np.generic, np.integer)):
                raw_value = int(raw_value)
            elif isinstance(raw_value, (np.floating)):
                raw_value = float(raw_value)

            explanation.append({
                "feature": col,
                "value": raw_value,
                "impact": float(val)
            })

        prediction = int(model.predict(df)[0])

        print("Model classes:", model.classes_)
        print("Prediction:", prediction)
        print("SHAP shape:", shap_values.shape if isinstance(shap_values, np.ndarray) else [sv.shape for sv in shap_values])
        print("Expected:", explainer.expected_value)
        
        decoded_proto = proto_encoder.inverse_transform([data['proto_encoded']])[0] if data['proto_encoded'] in proto_encoder.transform(proto_encoder.classes_) else "-"
        decoded_sig = sig_encoder.inverse_transform([data['signature_encoded']])[0] if data['signature_encoded'] in sig_encoder.transform(sig_encoder.classes_) else "-"

        return jsonify({
            "explanation": explanation,
            "prediction": prediction,
            "decoded": {
                "proto": decoded_proto,
                "signature": decoded_sig
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/decode_value", methods=["POST"])
def decode_value():
    try:
        data = request.json
        proto_val = data.get("proto_encoded")
        sig_val = data.get("signature_encoded")

        proto_name = proto_encoder.inverse_transform([proto_val])[0] if proto_val is not None else None
        sig_name = sig_encoder.inverse_transform([sig_val])[0] if sig_val is not None else None

        return jsonify({
            "proto_encoded": proto_val,
            "proto_decoded": proto_name,
            "signature_encoded": sig_val,
            "signature_decoded": sig_name
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/encoders_info", methods=["GET"])
def encoders_info():
    try:
        proto_dict = {i: v for i, v in enumerate(proto_encoder.classes_)}
        sig_dict = {i: v for i, v in enumerate(sig_encoder.classes_)}

        return jsonify({
            "proto_encoder": proto_dict,
            "signature_encoder": sig_dict
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)