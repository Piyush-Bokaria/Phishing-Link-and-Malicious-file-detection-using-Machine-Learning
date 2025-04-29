# 🔐 Phishing Link and Malware Detection using Machine Learning

This project is a web-based application built with Flask that detects:
- Whether a given **URL is phishing or legitimate**, and
- Whether an uploaded **`.exe` file is malicious or safe** based on static PE (Portable Executable) analysis.

It utilizes machine learning models trained on cybersecurity datasets and integrates user-friendly prediction endpoints.

## 🚀 Features

- 🛡️ **Phishing URL Detection**  
  Uses handcrafted features and ML classification to flag potentially malicious links.

- 🧬 **Malware File Detection (.exe)**  
  Performs static analysis of PE files using `pefile` to extract entropy, headers, and section-based features.

- 📈 **Confidence Scoring**  
  Each prediction returns a confidence level for transparency.

- 🖥️ **Web Interface**  
  Upload files or enter URLs directly via the Flask web UI.

## 🧠 Machine Learning Models

- **Phishing Detection:** Trained with features like URL length, character ratios, shortening services, TLDs, etc.
- **Malware Detection:** Trained using features extracted from the executable’s PE headers and entropy values.

Model files:
- `./Models/rf-and-gdb.pkl` (Phishing detection)
- `./Models/malware_detection.pkl` (Malware detection)

## 🛠️ Tech Stack

- **Backend:** Python, Flask
- **ML Libraries:** numpy, scikit-learn, pandas, pefile, sklearn.ensemble, seaborn, pickle, urllib.parse, re, from werkzeug.utils, secure_filename, pefile, math, os, atexit, shutil, threading, time, 
- **Frontend:** HTML, CSS, JS (via Flask templates)

## 📂 Folder Structure
this is the folder structure:

├───Models
│   ├───malware_detection.pkl 
│   └───rf-and-gdb.pkl
├───model_training
│   ├───Malicious_file
│       ├───dataset_malwares.csv
│       └───malware_model.ipynb
│   └───Phishing_Link
│       ├───dataset_phishing.csv
│       └───Phishing Website Detection_Models & Training.ipynb
├───outputs
├───static
│   ├───css
│       ├───main.css
│       ├───main.sass
│       ├───base
│       ├───fonts
│       ├───layouts
│       └───modules
│   ├───images
│   ├───img
│   └───js
│       ├───functions-min.js
│       └───functions.js
└───templates
│   ├───index.html
└───app.py
└───requirements.txt