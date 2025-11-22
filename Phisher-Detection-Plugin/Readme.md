# 🎣 Phishing Detector (ML Ensemble + API Fusion)

## 🌟 Project Overview

This project is a sophisticated **Phishing Detection System** delivered as a browser extension. It utilizes a three-pronged defense strategy for real-time URL analysis:

1.  **Local Machine Learning Model:** A trained ensemble classifier analyzes extracted URL features.
2.  **External Threat Intelligence:** Integrates verdicts from the **Google Safe Browsing (GSB)** and **VirusTotal (VT)** APIs.
3.  **Majority Vote Fusion:** The final security verdict (Phishing, Legitimate, or Suspicious) is determined by a **2-out-of-3 majority vote**, significantly enhancing robustness and reliability over a single model's prediction.

The system is split into a Python/Flask **Backend API** (for heavy lifting and ML inference) and a pure JavaScript/HTML **Frontend** (as a browser extension).

---

## 🏗️ Monorepo Structure and File Breakdown

The repository is organized into distinct `backend` and `frontend` directories, maintaining a clean separation of concerns.

### ⚙️ Backend Files (`backend/` folder)

This component hosts the core logic, data, and machine learning pipeline, managed by a Flask API service.

| File Name | Description |
| :--- | :--- |
| **`api.py`** | **Flask API Service:** The central application. It handles incoming URL analysis requests, loads the serialized ML model and scaler, performs feature extraction, integrates GSB/VT checks, and fuses the three verdicts into a final JSON response. |
| **`train_model.py`** | **Model Training Script:** This script prepares the `Phishing_Legitimate_full.csv` data, trains the **Stacking Classifier** ensemble (including models like XGBoost/LightGBM), evaluates performance, and saves the three necessary production artifacts (`.pkl` files). |
| **`config.ini`** | **Configuration File:** Stores sensitive, environment-specific variables, primarily the **Google Safe Browsing API Key** and **VirusTotal API Key**, which are loaded by `api.py`. |
| **`Phishing_Legitimate_full.csv`**| **Training Data:** The full dataset used to train the machine learning model, containing various features extracted from URLs and their corresponding security labels. |
| **`phishing_stacking_model.pkl`**| **Trained ML Model:** The serialized binary object containing the complete, production-ready **Stacking Classifier ensemble**. This is loaded by `api.py` for local, high-speed classification. |
| **`scaler.pkl`** | **Feature Scaler:** A serialized `StandardScaler` object, fit during the training process. It is critical for transforming raw URL features at inference time in `api.py` to ensure consistency with the model's training data scale. |
| **`feature_names.pkl`** | **Feature Order List:** A serialized list containing the exact names and order of the features that the `scaler.pkl` and ML model expect as input. This prevents critical feature misalignment during real-time prediction. |

### 💻 Frontend Files (`frontend/` folder)

This component contains the files necessary to run the browser extension UI (tested primarily on Chrome/Chromium-based browsers).

| File Name | Description |
| :--- | :--- |
| **`manifest.json`** | **Extension Metadata:** The required configuration file (Manifest V3). It defines the extension's name, version, permissions (`activeTab`, `storage`), and specifies the `default_popup` (`popup.html`). Crucially, it lists `http://127.0.0.1:5000/*` under `host_permissions` to allow communication with the local backend API. |
| **`popup.html`** | **User Interface Markup:** Provides the HTML structure for the browser extension's pop-up window, including the URL input field, the "Analyze" button, and the dedicated display areas for the final verdict and the three independent votes. |
| **`popup.js`** | **UI Logic and API Interaction:** The main JavaScript logic. It handles button clicks, uses the browser API to retrieve the current tab's URL, sends a `fetch` request to the running Flask API (`http://127.0.0.1:5000/analyze`), and dynamically updates the `popup.html` with the results. |
| **`style.css` (Assumed)**| **Styling Sheet:** (Not uploaded, but inferred from `popup.html`). Provides the visual styling (CSS) for the extension's UI to ensure a clean and responsive design. |

---

## 🛠️ Setup and Running the Project

### 1. Backend Service Setup

The Flask API must be running locally for the browser extension to function.

1.  **Prerequisites:** Ensure you have **Python 3** and the necessary dependencies (e.g., `Flask`, `scikit-learn`, `xgboost`, `lightgbm`, `pandas`, `joblib`, `requests`, `tldextract`) installed in a virtual environment.
2.  **API Keys:** Obtain and securely insert your **Google Safe Browsing API Key** and **VirusTotal API Key** into the `backend/config.ini` file.
3.  **Run the API:** Navigate to the `backend` directory in your terminal and start the server:
    ```bash
    python api.py
    ```
    The service will start listening on `http://127.0.0.1:5000/`. **Keep this terminal window open.**

### 2. Frontend (Browser Extension) Installation

The extension is loaded directly into your browser's development environment.

1.  **Open Browser Extensions:** In a Chromium-based browser (Chrome, Edge), navigate to `chrome://extensions/`.
2.  **Enable Developer Mode:** Toggle the **"Developer mode"** switch (usually in the top right corner).
3.  **Load Unpacked Extension:** Click the **"Load unpacked"** button.
4.  **Select Folder:** Browse to the project's **`frontend`** folder and select it.
5.  The **"Phishing Detector"** icon should appear in your browser's toolbar, ready to analyze URLs by communicating with your running backend API.

---

## ⚖️ License

[Insert your chosen license here, e.g., MIT, Apache 2.0, or leave blank if undecided.]
