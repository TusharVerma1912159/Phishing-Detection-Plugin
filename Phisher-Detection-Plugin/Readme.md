# 🎣 Phishing Detector: ML Ensemble & API Fusion System

## 🌟 1. Project Overview

This project implements a robust, real-time URL analysis system designed to detect phishing attempts, packaged as a lightweight browser extension. The core innovation lies in its defensive architecture, which moves beyond a single machine learning prediction.

The final security verdict is based on a **Majority Vote** from three distinct analysis sources:

1.  **Local Machine Learning Model:** A highly accurate ensemble classifier.
2.  **Google Safe Browsing (GSB):** A widely trusted external threat intelligence API.
3.  **VirusTotal (VT):** A comprehensive URL scanning service leveraging multiple security vendors.

The system is architecturally split into a **Python/Flask Backend API** (for heavy-duty machine learning and external API integration) and a **JavaScript/HTML Frontend** (the browser extension UI).

---

## 🏗️ 2. Detailed File Breakdown

The project adheres to a clean, decoupled Monorepo structure, separating the core service logic from the user interface.

### A. Backend Component (`backend/` folder)

This component contains the machine learning assets, configuration, and the Flask API that serves the analysis requests.

| File Name | Purpose and Technical Description |
| :--- | :--- |
| **`api.py`** | **Flask API Service Core:** This is the main server file that runs on `http://127.0.0.1:5000/`. It handles incoming `POST` requests containing a URL, loads the serialized ML model/scaler, performs real-time feature extraction on the input URL, queries the Google Safe Browsing and VirusTotal APIs, and applies the **2-out-of-3 majority vote logic** to produce the final verdict. |
| **`train_model.py`** | **Model Training Script:** The script responsible for reading the CSV data, splitting it into training/testing sets, fitting the `StandardScaler`, training the **Stacking Classifier** ensemble (composed of base learners like XGBoost and LightGBM), evaluating its performance, and serializing the three necessary production artifacts (`.pkl` files). |
| **`config.ini`** | **Configuration File:** Stores necessary credentials in the `[API_KEYS]` section, specifically the confidential **GOOGLE_API_KEY** and **VIRUSTOTAL_API_KEY** required for external threat intelligence checks within `api.py`. |
| **`Phishing_Legitimate_full.csv`**| **Training Data:** The raw dataset used for the ML pipeline, featuring 50+ computed features extracted from URLs (e.g., `NumDots`, `UrlLength`, `PathLevel`) and the binary `CLASS_LABEL` (0 or 1). |
| **`phishing_stacking_model.pkl`**| **Trained ML Model:** The serialized binary file containing the complete, pre-trained **`sklearn.ensemble.StackingClassifier`**. This is loaded by `api.py` for high-speed, local URL classification. |
| **`scaler.pkl`** | **Feature Scaler:** The serialized `sklearn.preprocessing.StandardScaler` object, fit exclusively on the training data. This must be used by `api.py` to normalize (scale) input features from a new URL before they are fed to the `phishing_stacking_model.pkl`. |
| **`feature_names.pkl`** | **Feature Order List:** A serialized list of feature names (`NumDots`, `SubdomainLevel`, etc.). It defines the **exact, canonical order** that the features must be arranged in when passed to the `scaler.pkl` and the ML model at inference time, preventing critical feature misalignment. |

### B. Frontend Component (`frontend/` folder)

This component is the Manifest V3 browser extension UI and logic.

| File Name | Purpose and Technical Description |
| :--- | :--- |
| **`manifest.json`** | **Extension Configuration:** Defines the extension's metadata, permissions (`activeTab`, `storage`), and sets `popup.html` as the main interface. Critically, it declares `http://127.0.0.1:5000/*` under `host_permissions` to allow the extension to send requests to the local Flask API. |
| **`popup.html`** | **User Interface (UI):** The HTML markup for the pop-up window. It contains an input box, buttons, and dedicated, structured display areas for the overall final verdict and the individual votes from the Model, GSB, and VT. |
| **`popup.js`** | **UI Logic and API Communication:** The client-side JavaScript that governs the extension's behavior. It retrieves the current tab's URL, sends the URL to the backend via a `fetch('http://127.0.0.1:5000/analyze', ...)` POST request, handles the JSON response, and dynamically renders the results and status chips on `popup.html`. |
| **`style.css`** | **Styling Sheet:** Provides the clean, professional visual styling (CSS) for all elements within `popup.html`, including the visual representation of status (Green/Red/Amber) for the verdict chips. |

---

## ⚙️ 3. Installation and Execution Guide

This project requires two separate components to be running concurrently: the Backend API and the Frontend Extension.

### STEP 1: Backend API Setup (Python Environment)

This procedure sets up the core analysis server.

1.  **Project Directory:** Ensure you are in the root directory of the project, which contains the `backend` and `frontend` folders.
2.  **Virtual Environment (Mandatory):** For isolation, create and activate a Python virtual environment.
    ```bash
    # Create the virtual environment
    python3 -m venv venv 
    
    # Activate the environment (macOS/Linux)
    source venv/bin/activate
    
    # Activate the environment (Windows - Command Prompt)
    # venv\Scripts\activate
    ```
3.  **Install Dependencies:** Install all required Python packages (e.g., `Flask`, `scikit-learn`, `joblib`, `requests`, `pandas`, `tldextract`, `xgboost`, `lightgbm`). If a `requirements.txt` file is not present, you must manually install these:
    ```bash
    pip install Flask scikit-learn joblib requests pandas numpy tldextract configparser xgboost lightgbm
    ```
4.  **API Key Configuration (Crucial):** Open the file **`backend/config.ini`**. You **must** replace the placeholder API keys with your valid, personal keys for Google Safe Browsing and VirusTotal.
    ```ini
    # backend/config.ini - Replace the entire strings after the = sign
    [API_KEYS]
    GOOGLE_API_KEY = YOUR_ACTUAL_GOOGLE_SAFE_BROWSING_KEY_HERE
    VIRUSTOTAL_API_KEY = YOUR_ACTUAL_VIRUSTOTAL_KEY_HERE
    ```
5.  **Run the Backend Service:** Navigate into the `backend` folder and start the Flask server.
    ```bash
    cd backend
    python api.py
    ```
    **Expected Output:** The console should show a message indicating the Flask application is running, typically on `http://127.0.0.1:5000/`. **Keep this terminal window open; the extension will not work if the server is stopped.**

### STEP 2: Frontend Extension Setup (Browser)

This procedure loads the extension into your browser in developer mode (tested on Chromium-based browsers like Chrome and Edge).

1.  **Open Extension Management:** Open your web browser (e.g., Chrome/Edge) and navigate to the extensions management page:
    * Type the URL: `chrome://extensions/`
2.  **Enable Developer Mode:** Locate the toggle switch labeled **"Developer mode"** (usually in the upper-right corner) and ensure it is **switched ON**.
3.  **Load the Extension:** Click the **"Load unpacked"** button that appears after enabling developer mode. 4.  **Select the Folder:** A file dialog will open. Navigate to your project folder and specifically select the **`frontend`** folder (the one containing `manifest.json`, `popup.html`, etc.). **Do not select the root folder; you must select the `frontend` folder.**
5.  **Verification:**
    * The extension, named **"Phishing Detector"**, will appear in your list of installed extensions.
    * A small icon (usually a shield or similar) will appear in your browser's toolbar.

### STEP 3: Usage

1.  **Open a Website:** Navigate to any website you wish to analyze in a new tab.
2.  **Click the Icon:** Click the **Phishing Detector** icon in your browser's toolbar to open the pop-up.
3.  **Analyze:**
    * Click the **"Current"** button to automatically populate the input field with the tab's URL.
    * Click the **"Analyze"** button to send the URL to your running Flask API (Step 1) for the three-way majority vote analysis.
4.  **Review Verdict:** The pop-up will display the final verdict (Phishing, Legitimate, or Suspicious) and the individual results from the Model, Google Safe Browsing, and VirusTotal.

---

## ⚖️ 4. License

[Insert your chosen license here, e.g., MIT, Apache 2.0, or leave blank if undecided.]
