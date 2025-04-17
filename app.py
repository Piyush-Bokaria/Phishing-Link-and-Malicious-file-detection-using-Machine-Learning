import os
import pickle
import joblib
import numpy as np
from flask import Flask, request, render_template, redirect, flash ,jsonify, abort, url_for
import urllib.parse
import re
from werkzeug.utils import secure_filename
import pefile
import array
import math
import sys
import argparse
import shutil, time
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)
app.secret_key = "secret123"
UPLOAD_FOLDER = './uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

malware_model = joblib.load("./Models/malware_detection.pkl")
with open("./Models/XGBoostClassifier.pickle.dat", "rb") as f:
    phishing_model = pickle.load(f)
FEATURES = ['e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc',
    'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc',
    'e_ovno', 'e_oemid', 'e_oeminfo', 'e_lfanew', 'NumberOfSections',
    'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader',
    'Characteristics', 'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion',
    'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
    'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', 'SectionAlignment',
    'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
    'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
    'MinorSubsystemVersion', 'SizeOfHeaders', 'CheckSum', 'SizeOfImage',
    'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit',
    'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes',
    'SuspiciousImportFunctions', 'SuspiciousNameSection', 'SectionsLength',
    'SectionMinEntropy', 'SectionMaxEntropy', 'SectionMinRawsize', 'SectionMaxRawsize',
    'SectionMinVirtualsize', 'SectionMaxVirtualsize', 'SectionMaxPhysical',
    'SectionMinPhysical', 'SectionMaxVirtual', 'SectionMinVirtual',
    'SectionMaxPointerData', 'SectionMinPointerData', 'SectionMaxChar',
    'SectionMainChar', 'DirectoryEntryImport', 'DirectoryEntryImportSize',
    'DirectoryEntryExport', 'ImageDirectoryEntryExport', 'ImageDirectoryEntryImport',
    'ImageDirectoryEntryResource', 'ImageDirectoryEntryException', 'ImageDirectoryEntrySecurity']


def extract_features(filepath):
    features = {}
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        raise ValueError("Invalid PE file.")


    for attr in ['e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc',
                 'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc',
                 'e_ovno', 'e_oemid', 'e_oeminfo', 'e_lfanew']:
        features[attr] = getattr(pe.DOS_HEADER, attr)

    features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
    features['PointerToSymbolTable'] = pe.FILE_HEADER.PointerToSymbolTable
    features['NumberOfSymbols'] = pe.FILE_HEADER.NumberOfSymbols
    features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    features['Characteristics'] = pe.FILE_HEADER.Characteristics

    for attr in ['Magic', 'MajorLinkerVersion', 'MinorLinkerVersion',
                 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
                 'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', 'SectionAlignment',
                 'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
                 'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion',
                 'MinorSubsystemVersion', 'SizeOfHeaders', 'CheckSum', 'SizeOfImage',
                 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve', 'SizeOfStackCommit',
                 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes']:
        features[attr] = getattr(pe.OPTIONAL_HEADER, attr)

    suspicious_keywords = ['LoadLibrary', 'GetProcAddress', 'VirtualAlloc', 'WriteProcessMemory']
    suspicious_count = 0
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and any(kw in imp.name.decode(errors="ignore") for kw in suspicious_keywords):
                    suspicious_count += 1
    except AttributeError:
        pass
    features['SuspiciousImportFunctions'] = suspicious_count

    sections = pe.sections
    features['SuspiciousNameSection'] = sum(1 for s in sections if b'.text' not in s.Name)
    features['SectionsLength'] = len(sections)
    entropies = [s.get_entropy() for s in sections]
    features['SectionMinEntropy'] = min(entropies) if entropies else 0
    features['SectionMaxEntropy'] = max(entropies) if entropies else 0
    raws = [s.SizeOfRawData for s in sections]
    features['SectionMinRawsize'] = min(raws) if raws else 0
    features['SectionMaxRawsize'] = max(raws) if raws else 0
    virtuals = [s.Misc_VirtualSize for s in sections]
    features['SectionMinVirtualsize'] = min(virtuals) if virtuals else 0
    features['SectionMaxVirtualsize'] = max(virtuals) if virtuals else 0
    physicals = [s.PointerToRawData for s in sections]
    features['SectionMinPhysical'] = min(physicals) if physicals else 0
    features['SectionMaxPhysical'] = max(physicals) if physicals else 0
    virtuals_addr = [s.VirtualAddress for s in sections]
    features['SectionMinVirtual'] = min(virtuals_addr) if virtuals_addr else 0
    features['SectionMaxVirtual'] = max(virtuals_addr) if virtuals_addr else 0
    ptr_data = [s.PointerToRelocations for s in sections]
    features['SectionMinPointerData'] = min(ptr_data) if ptr_data else 0
    features['SectionMaxPointerData'] = max(ptr_data) if ptr_data else 0
    chrs = [s.Characteristics for s in sections]
    features['SectionMinChar'] = min(chrs) if chrs else 0
    features['SectionMaxChar'] = max(chrs) if chrs else 0
    features['SectionMainChar'] = max(set(chrs), key=chrs.count) if chrs else 0

    directory_entries = {
    'ImageDirectoryEntryExport': pefile.IMAGE_DIRECTORY_ENTRY_EXPORT,
    'ImageDirectoryEntryImport': pefile.IMAGE_DIRECTORY_ENTRY_IMPORT,
    'ImageDirectoryEntryResource': pefile.IMAGE_DIRECTORY_ENTRY_RESOURCE,
    'ImageDirectoryEntryException': pefile.IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    'ImageDirectoryEntrySecurity': pefile.IMAGE_DIRECTORY_ENTRY_SECURITY
    }

    for key, idx in directory_entries.items():
        try:
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
            features[key] = 1 if directory.VirtualAddress > 0 else 0
        except Exception:
            features[key] = 0

    try:
        features['DirectoryEntryImport'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        features['DirectoryEntryImportSize'] = sum([entry.struct.Size for entry in pe.DIRECTORY_ENTRY_IMPORT])
    except AttributeError:
        features['DirectoryEntryImport'] = 0
        features['DirectoryEntryImportSize'] = 0

    try:
        features['DirectoryEntryExport'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        features['DirectoryEntryExport'] = 0

    return [features.get(f, 0) for f in FEATURES]

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

@app.route('/predict_malware', methods=['POST'])
def upload_file():
    try:
        if 'malicious' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['malicious']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        filepath = os.path.normpath(os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename)))

        file.save(filepath)

        # Extract features using your function
        features = extract_features(filepath)

        # List of model-required features (replace with your full updated list)
        feature_list = [
            'e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc',
            'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc',
            'e_ovno', 'e_oemid', 'e_oeminfo', 'e_lfanew', 'NumberOfSections',
            'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader',
            'Characteristics', 'Magic', 'MajorLinkerVersion', 'MinorLinkerVersion',
            'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
            'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', 'SectionAlignment',
            'FileAlignment', 'MajorOperatingSystemVersion',
            'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion',
            'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfHeaders',
            'CheckSum', 'SizeOfImage', 'Subsystem', 'DllCharacteristics',
            'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve',
            'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes',
            'SuspiciousImportFunctions', 'SuspiciousNameSection', 'SectionsLength',
            'SectionMinEntropy', 'SectionMaxEntropy', 'SectionMinRawsize',
            'SectionMaxRawsize', 'SectionMinVirtualsize', 'SectionMaxVirtualsize',
            'SectionMaxPhysical', 'SectionMinPhysical', 'SectionMaxVirtual',
            'SectionMinVirtual', 'SectionMaxPointerData', 'SectionMinPointerData',
            'SectionMaxChar', 'SectionMainChar', 'DirectoryEntryImport',
            'DirectoryEntryImportSize', 'DirectoryEntryExport',
            'ImageDirectoryEntryExport', 'ImageDirectoryEntryImport',
            'ImageDirectoryEntryResource', 'ImageDirectoryEntryException',
            'ImageDirectoryEntrySecurity'
        ]

        input_features = [features.get(k, 0) for k in feature_list]

        # Predict
        prediction = malware_model.predict([input_features])[0]
        print(prediction)
        label = 'malicious' if prediction == 1 else 'legitimate'

        return jsonify({'prediction': label})
    
    except Exception as e:
        print("Error during malware prediction:", e)
        return jsonify({'error': str(e)}), 500

@app.route('/predict_url', methods=['GET', 'POST'])
def predict_url():
    url = request.form.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features = extract_url_features(url)
    prediction = phishing_model.predict(features)[0]
    print(prediction)
    label = 'Phishing Link' if prediction == 1 else 'Legitimate'

    return jsonify({
        "url": url,
        "prediction": label
    })

if __name__ == '__main__':
    app.run(debug=True)