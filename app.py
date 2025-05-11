import pickle
import pandas as pd
import numpy as np
from flask import Flask, request, render_template, jsonify, redirect, url_for
import urllib.parse
import re
from werkzeug.utils import secure_filename
import pefile
import math
import os
import atexit
import shutil
import threading
import time


app = Flask(__name__)
app.secret_key = "secret123"
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024

# Load model
with open("./Models/rf-and-gdb.pkl", "rb") as f:
    phishing_model = pickle.load(f)

with open("./Models/malware_detection.pkl", "rb") as f:
    model = pickle.load(f)

shortening_services = r"(bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net)"
required_features = ['Characteristics',
                     'SizeOfStackReserve',
                     'SectionMinEntropy',
                     'DllCharacteristics',
                     'SizeOfHeaders']

# Function to extract features
def extract_features(url):
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    def count_char(string, char):
        return string.count(char)

    def digit_ratio(s):
        return sum(c.isdigit() for c in s) / len(s) if s else 0

    features = {
        'length_url': len(url),
        'length_hostname': len(hostname),
        'ip': 1 if re.fullmatch(r'(\d{1,3}\.){3}\d{1,3}', hostname) else 0,
        'nb_dots': count_char(url, '.'),
        'nb_hyphens': count_char(url, '-'),
        'nb_at': count_char(url, '@'),
        'nb_qm': count_char(url, '?'),
        'nb_and': count_char(url, '&'),
        'nb_or': count_char(url, '|'),
        'nb_eq': count_char(url, '='),
        'nb_underscore': count_char(url, '_'),
        'nb_tilde': count_char(url, '~'),
        'nb_percent': count_char(url, '%'),
        'nb_slash': count_char(url, '/'),
        'nb_star': count_char(url, '*'),
        'nb_colon': count_char(url, ':'),
        'nb_comma': count_char(url, ','),
        'nb_semicolumn': count_char(url, ';'),
        'nb_dollar': count_char(url, '$'),
        'nb_space': count_char(url, ' '),
        'nb_www': 1 if 'www' in url else 0,
        'nb_com': url.count('.com'),
        'nb_dslash': url.count('//'),
        'http_in_path': 1 if 'http' in path.lower() else 0,
        'https_token': 1 if 'https' in hostname else 0,
        'ratio_digits_url': digit_ratio(url),
        'ratio_digits_host': digit_ratio(hostname),
        'punycode': 1 if 'xn--' in url else 0,
        'shortening_service': 1 if re.search(shortening_services, url) else 0,
        'path_extension': 1 if re.search(r'\.(exe|zip|scr|rar|tar|gz|apk|msi|bat|dll)$', path.lower()) else 0,
        'phish_hints': 1 if re.search(r'(secure|account|webscr|login|signin|banking|update|confirm|security)', url.lower()) else 0,
        'domain_in_brand': 0, 
        'brand_in_subdomain': 0, 
        'brand_in_path': 0, 
        'suspecious_tld': 1 if re.search(r'\.(zip|review|country|kim|cricket|science|work|party|gq|link)$', hostname.lower()) else 0
    }

    return pd.DataFrame([features])

# Compute entropy
def get_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

def delayed_delete(path, delay=3):
    def _delete():
        time.sleep(delay)
        try:
            os.remove(path)
        except Exception as e:
            print(f"Delayed delete failed: {e}")
    threading.Thread(target=_delete).start()

# Extract PE features
def extract_pe_features(filepath):
    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories()  
        characteristics = pe.FILE_HEADER.Characteristics
        size_of_stack_reserve = pe.OPTIONAL_HEADER.SizeOfStackReserve

        min_entropy = float('inf')
        for section in pe.sections:
            entropy = get_entropy(section.get_data())
            min_entropy = min(min_entropy, entropy)

        dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        
        pe.close()  

        return {
            'Characteristics': characteristics,
            'SizeOfStackReserve': size_of_stack_reserve,
            'SectionMinEntropy': min_entropy,
            'DllCharacteristics': dll_characteristics,
            'SizeOfHeaders': size_of_headers
        }

    except Exception as e:
        print(f"Error while parsing PE file: {e}")
        return None


@app.route("/predict_url", methods=['POST'])
def predict_url():
    url = request.form.get("phishing-link")
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    features = extract_features(url)
    prediction_prob = phishing_model.predict_proba(features)[0][1]
    prediction_class = phishing_model.predict(features)[0]

    result = {
        "url": url,
        "prediction": "Phishing" if prediction_class == 1 else "Legitimate",
        "confidence": round(prediction_prob, 4) if prediction_class == 1 else round(1 - prediction_prob, 4)
    }
    return jsonify(result)

@app.before_request
def setup_upload_folder():
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

@atexit.register
def cleanup_upload_folder():
    shutil.rmtree(UPLOAD_FOLDER, ignore_errors=True)

@app.route("/predict_malware", methods=['GET', 'POST'])
def predict_malware():
    if request.method == 'POST':
        file = request.files.get('file')  
        if not file:
            return jsonify({'error': 'No file uploaded'}), 400

        upload_folder = 'uploads'
        os.makedirs(upload_folder, exist_ok=True)  # Ensure uploads folder exists

        filename = secure_filename(file.filename)  # This is VERY important
        
        file_path = os.path.join(upload_folder, filename)
        file.save(file_path)
    

        if not filename.lower().endswith('.exe'):
            return jsonify({"error": "Only .exe files are supported"}), 400

        try:
            features_dict = extract_pe_features(file_path)
            if not features_dict:
                return jsonify({'error': 'Could not extract features. Please upload a valid PE (.exe) file.'}), 400

            df = pd.DataFrame([features_dict])[required_features]
            prediction_prob = model.predict_proba(df)[0][1]
            prediction_class = model.predict(df)[0]

            result = {
                "filename": filename,
                "prediction": "Malicious" if prediction_class == 1 else "Legitimate",
                "confidence": round(prediction_prob, 4) if prediction_class == 1 else round(1 - prediction_prob, 4)
            }
            
            delayed_delete(file_path)
            
            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    else:
        return render_template('index.html')

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)