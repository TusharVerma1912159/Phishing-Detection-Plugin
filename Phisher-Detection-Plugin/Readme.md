\# 🎣 Phishing Detector (ML + API Fusion)



\*\*Description:\*\* This project implements a real-time URL phishing detection system delivered via a browser extension. The core analysis engine runs on a local Flask API, leveraging a trained Machine Learning (ML) ensemble model and integrating external threat intelligence APIs (Google Safe Browsing and VirusTotal) for a highly reliable majority-vote verdict.



---



\## 🚀 Key Features



\* \*\*Ensemble ML Model:\*\* Uses a powerful \*\*Stacking Classifier\*\* to analyze extracted URL features.

\* \*\*API Fusion:\*\* Combines predictions from the local ML model, Google Safe Browsing (GSB), and VirusTotal (VT).

\* \*\*Majority Vote:\*\* The final verdict (Phishing, Legitimate, or Suspicious) is determined by a \*\*2-out-of-3 majority vote\*\*, enhancing accuracy and robustness.

\* \*\*Browser Extension:\*\* A clean, user-friendly interface that allows for one-click analysis of the current tab's URL.



---



\## 📁 Project File Breakdown



The repository follows a Monorepo structure with clear separation between the service logic and the UI.



\### ⚙️ Backend (`backend/` folder)



| File Name | Purpose and Description |

| :--- | :--- |

| \*\*`api.py`\*\* | \*\*Flask API Service:\*\* The core of the service. It handles URL analysis requests, loads the ML model, fetches external threat data, and applies the majority-vote logic to return a final JSON verdict. |

| \*\*`train\\\_model.py`\*\* | \*\*Model Training Script:\*\* Used to prepare the data, train the ensemble Stacking Classifier model, evaluate it, and serialize the model and data artifacts. |

| \*\*`Phishing\\\_Legitimate\\\_full.csv`\*\*| \*\*Training Data:\*\* The dataset containing URL features and the corresponding `CLASS\\\_LABEL` (Phishing or Legitimate) used for model training. |

| \*\*`phishing\\\_stacking\\\_model.pkl`\*\*| \*\*Trained ML Model:\*\* The serialized binary file containing the final, trained Stacking Classifier ensemble used for real-time local prediction. |

| \*\*`scaler.pkl`\*\* | \*\*Feature Scaler:\*\* A serialized `StandardScaler` object used to normalize new URL features at inference time, ensuring data consistency with the model's training. |

| \*\*`feature\\\_names.pkl`\*\* | \*\*Feature Order List:\*\* A serialized list defining the exact, required order of the input features expected by the `scaler.pkl` and the ML model. |

| \*\*`config.ini`\*\* | \*\*Configuration File:\*\* Stores required credentials, specifically API keys for external services like Google Safe Browsing and VirusTotal. \*\*(NOTE: This file should be kept private if possible.)\*\* |



\### 💻 Frontend (`frontend/` folder)



| File Name | Purpose and Description |

| :--- | :--- |

| \*\*`manifest.json`\*\* | \*\*Extension Configuration:\*\* The required file for a browser extension (Manifest V3). It defines the name, permissions (`activeTab`, `storage`), and specifies `popup.html` as the main interface. |

| \*\*`popup.html`\*\* | \*\*User Interface (UI):\*\* Provides the HTML structure and layout for the browser extension's pop-up window. |

| \*\*`popup.js`\*\* | \*\*UI Logic and API Interaction:\*\* Handles user events, captures the current tab's URL, sends the analysis request to the backend API, and renders the final verdict. |



---



\## ⚙️ Setup Instructions (For Users)



\### 1. Backend Service (Flask API)



1\.  \*\*Prerequisites:\*\* Install Python 3 and the required libraries (e.g., `Flask`, `scikit-learn`, `joblib`, `requests`, `pandas`, etc.).

2\.  \*\*API Keys:\*\* Edit `backend/config.ini` and insert your personal \*\*Google Safe Browsing\*\* and \*\*VirusTotal\*\* API keys.

3\.  \*\*Run:\*\* The service must be running locally on `http://127.0.0.1:5000/` for the extension to work.



\### 2. Frontend Extension (Browser)



1\.  \*\*Open Extensions:\*\* Navigate to your browser's extensions page (e.g., `chrome://extensions/`).

2\.  \*\*Enable Developer Mode:\*\* Toggle the \*\*"Developer mode"\*\* switch on.

3\.  \*\*Load Extension:\*\* Click the \*\*"Load unpacked"\*\* button and select the \*\*`frontend`\*\* folder from this project.

4\.  The extension icon will appear in your toolbar, ready to analyze URLs.

