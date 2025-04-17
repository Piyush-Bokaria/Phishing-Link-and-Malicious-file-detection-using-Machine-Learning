import os
import pickle
import joblib
import numpy as np
from flask import Flask, request, render_template, redirect, flash ,jsonify
import urllib.parse
import re
from werkzeug.utils import secure_filename
import pefile

def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path)

        features = []
        features.append(pe.FILE_HEADER.Characteristics)
        features.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
        features.append(min([s.get_entropy() for s in pe.sections]))
        features.append(pe.OPTIONAL_HEADER.DllCharacteristics)
        features.append(pe.OPTIONAL_HEADER.SizeOfHeaders)

        return np.array(features).reshape(1, -1)
    except Exception as e:
        print("Error in PE feature extraction:", e)
        return None

app = Flask(__name__)
app.secret_key = "secret123"
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

malware_model = joblib.load("./Models/malware_detection.pkl")
with open("./Models/XGBoostClassifier.pickle.dat", "rb") as f:
    phishing_model = pickle.load(f)

def extract_url_features(url):
    features = []

    # Feature 1: Presence of IP address in URL
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)

    # Feature 2: Presence of '@' symbol
    features.append(1 if "@" in url else 0)

    # Feature 3: URL Length
    features.append(len(url))

    # Feature 4: URL Depth (number of '/' in path)
    parsed_url = urllib.parse.urlparse(url)
    features.append(parsed_url.path.count('/'))

    # Feature 5: Redirection ("//" appears in the URL path)
    features.append(1 if "//" in parsed_url.path else 0)

    # Feature 6: Presence of "https" in domain name
    features.append(1 if "https" in parsed_url.netloc else 0)

    # Feature 7: Presence of TinyURL
    features.append(1 if "tinyurl" in url else 0)

    # Feature 8: Presence of prefix or suffix in domain (e.g., 'paypal-secure.com')
    features.append(1 if '-' in parsed_url.netloc else 0)

    # Feature 9: DNS Record (For now, assume domain exists)
    features.append(1)  # You can replace with actual DNS lookup

    # Feature 10: Web Traffic (Assume 1 for now, replace with actual traffic check)
    features.append(1)  

    # Feature 11: Domain Age (Assume 1 for now, replace with actual WHOIS check)
    features.append(1)  

    # Feature 12: Domain End Period (Assume 1 for now, replace with actual WHOIS check)
    features.append(1)  

    # Feature 13: Presence of iFrame (Assume 0 for now, replace with actual webpage analysis)
    features.append(0)

    # Feature 14: Mouse Over Effect (Assume 0 for now, replace with actual JavaScript analysis)
    features.append(0)

    # Feature 15: Right Click Disabled (Assume 0 for now, replace with actual webpage analysis)
    features.append(0)

    # Feature 16: Web Forwards (Assume 0 for now, replace with actual checks)
    features.append(0)

    return np.array(features).reshape(1, -1) 

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict_malware', methods=['GET', 'POST'])
def predict_file():
    if 'malicious' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['malicious']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    features = extract_pe_features(filepath)
    if features is None:
        return jsonify({'error': 'Unable to extract features from file'}), 500

    prediction = malware_model.predict(features)[0]
    print(prediction)
    label = 'Malicious File' if prediction == 0 else 'Benign File'

    return jsonify({'prediction': label})

@app.route('/predict_url', methods=['GET', 'POST'])
def predict_url():
    url = request.form.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features = extract_url_features(url)
    prediction = phishing_model.predict(features)[0]
    print(prediction)
    label = 'Phishing Link' if prediction == 0 else 'Legitimate'

    return jsonify({
        "url": url,
        "prediction": label
    })

if __name__ == '__main__':
    app.run(debug=True)