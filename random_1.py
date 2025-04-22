import pickle
import pandas as pd
from flask import Flask, request, render_template, jsonify, redirect, url_for
from werkzeug.utils import secure_filename
import pefile
import math
import os
import atexit
import shutil


app = Flask(__name__)
app.secret_key = "secret123"
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 


with open("./Models/malware_detection.pkl", "rb") as f:
    model = pickle.load(f)
    
required_features = ['Characteristics',
                     'SizeOfStackReserve',
                     'SectionMinEntropy',
                     'DllCharacteristics',
                     'SizeOfHeaders']

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

# Extract PE features
def extract_pe_features(filepath):
    try:
        pe = pefile.PE(filepath)
        characteristics = pe.FILE_HEADER.Characteristics
        size_of_stack_reserve = pe.OPTIONAL_HEADER.SizeOfStackReserve

        min_entropy = float('inf')
        for section in pe.sections:
            entropy = get_entropy(section.get_data())
            min_entropy = min(min_entropy, entropy)

        dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics
        size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders

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


@app.route('/upload', methods=['POST'])
def upload_file():
    uploaded_file = request.files['file']
    if uploaded_file.filename != '':
        filename = secure_filename(uploaded_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        uploaded_file.save(file_path)
    return redirect(url_for('home'))

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

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
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
                "confidence": round(prediction_prob, 4)
            }
            print(result)
            
            os.remove(file_path)
            
            return jsonify(result)
        except Exception as e:
            # Handle any unexpected errors
            return jsonify({'error': str(e)}), 500
    else:
        render_template('index.html')

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)