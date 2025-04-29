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

```
├───Models
│   ├───malware_detection.pkl 
│   └───rf-and-gdb.pkl
├───model_training
│   ├───Malicious_file
│   │   ├───dataset_malwares.csv
│   │   └───malware_model.ipynb
│   └───Phishing_Link
│       ├───dataset_phishing.csv
│       └───Phishing Website Detection_Models & Training.ipynb
├───outputs
├───static
│   ├───css
│   │   ├───main.css
│   │   ├───main.sass
│   │   ├───base
│   │   ├───fonts
│   │   ├───layouts
│   │   └───modules
│   ├───images
│   ├───img
│   └───js
│       ├───functions-min.js
│       └───functions.js
├───templates
│   └───index.html
├───app.py
└───requirements.txt
```


# 🛠️ Installation & Setup
## 🔁 Clone the repository

git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name

## 📦 Create a virtual environment (recommended)

## Create a virtual environment
``` python -m venv venv ```

## Activate the virtual environment
### On Windows
```venv\Scripts\activate```

### On macOS/Linux
```source venv/bin/activate```

## 📥 Install dependencies

```
pip install -r requirements.txt
```

## ▶️ Run the Application
```
python app.py
```

Once running, open your browser and go to:

```http://127.0.0.1:5000/```

📌 Notes:

1. Only .exe files are accepted for malware detection.

2. Ensure that the uploaded .exe files are not locked by another process before submission.

3. A maximum file size of 200 MB is enforced.

4. URL detection supports typical phishing pattern identification based on feature extraction.

🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.