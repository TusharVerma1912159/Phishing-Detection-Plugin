## 🎣 Phishing Detector: ML Ensemble & API Fusion System (A Complete Guide)

### 🌟 1. Project Overview

This project implements a robust, real-time **URL phishing detection system** packaged as a browser extension. Its core strength is its **Majority Vote architecture**, which integrates three distinct analysis sources to provide a reliable security verdict, minimizing dependence on any single source:

1.  **Local Machine Learning Model:** A high-accuracy stacking ensemble classifier.
2.  **Google Safe Browsing (GSB):** External threat intelligence API.
3.  **VirusTotal (VT):** Comprehensive multi-vendor URL scanning service.

The final verdict is determined by a **2-out-of-3 majority**, classifying the URL as **Phishing**, **Legitimate**, or **Suspicious**. The architecture is split into a **Python/Flask Backend API** and a JavaScript/HTML **Frontend** extension.

---

### 🏗️ 2. Detailed File Breakdown by Component

The repository follows a clean, decoupled structure. **Note:** The extension files are located directly within the **`frontend/`** folder.

#### A. Backend Component (`backend/` folder)

This component contains the core Python logic, machine learning assets, and the Flask API service.

| File Name | Purpose and Technical Description |
| :--- | :--- |
| **`api.py`** | **Flask API Service Core:** Runs on `http://127.0.0.1:5000/`. It handles URL requests, loads the ML model/scaler, performs real-time feature extraction, queries GSB and VT APIs, and applies the **majority vote fusion logic**. |
| **`train_model.py`** | **Model Training Script:** Script to prepare data, train the **Stacking Classifier** ensemble, and serialize the final model, scaler, and feature list as `.pkl` files. |
| **`config.ini`** | **Configuration File:** Stores the necessary **GOOGLE\_API\_KEY** and **VIRUSTOTAL\_API\_KEY** for external threat checks. **Placeholders must be replaced before use**. |
| **`Phishing_Legitimate_full.csv`**| **Training Data:** The raw dataset used for ML training, containing 50+ computed URL features and the binary `CLASS_LABEL`. |
| **`phishing_stacking_model.pkl`**| **Trained ML Model:** The serialized **`StackingClassifier`** object loaded by `api.py` for high-speed, local classification. |
| **`scaler.pkl`** | **Feature Scaler:** The serialized `StandardScaler` object used to **normalize incoming URL features** in `api.py` before model input, ensuring data consistency. |
| **`feature_names.pkl`** | **Feature Order List:** A serialized list that defines the **exact, mandatory order** of features expected by the model, preventing critical column misalignment during inference. |

#### B. Frontend Component (`frontend/` folder)

This component is the Manifest V3 browser extension UI and logic.

| File Name | Location | Purpose and Technical Description |
| :--- | :--- | :--- |
| **`manifest.json`** | `.../frontend/` | Defines metadata and permissions. Includes `host_permissions` for **`http://127.0.0.1:5000/*`** to enable API communication. |
| **`popup.html`** | `.../frontend/` | HTML markup for the pop-up. Includes structured display areas for the Final Verdict and the three individual votes. |
| **`popup.js`** | `.../frontend/` | Client-side logic. It captures the URL (using `chrome.tabs.query`), sends it to the Flask API via `fetch()`, and dynamically updates the UI based on the JSON response. |
| **`style.css`** | `.../frontend/` | Provides the professional visual styling (CSS) for all UI elements in `popup.html`, including the status coloring for the verdict chips. |

---

### ⚙️ 3. Installation and Execution Guide (Step-by-Step)

The system is a two-part application. Both the backend service and the frontend extension **must** be running concurrently.

#### STEP 1: Backend API Setup (Python)

This sets up the core analysis server.

1.  **Prerequisites:** Ensure **Python 3** is installed. Activate a virtual environment and install the required libraries:
    ```bash
    # Example installation of core libraries:
    pip install Flask scikit-learn joblib requests pandas numpy tldextract configparser xgboost lightgbm
    ```
2.  **Configure API Keys (Critical):**
    * Open **`backend/config.ini`**.
    * **Replace the placeholder strings** for `GOOGLE_API_KEY` and `VIRUSTOTAL_API_KEY` with your actual, valid API keys. The application will not function without them.
3.  **Run the Backend Service:** Navigate into the **`backend`** folder using your terminal/command prompt and execute the main API file:
    ```bash
    # Navigate to the backend directory
    cd backend
    python api.py
    ```
    **Expected State:** The server must be actively running and listening on **`http://127.0.0.1:5000/`**. **Do not close this terminal window.**

#### STEP 2: Frontend Extension Setup (Browser)

This loads the extension into your browser's developer environment.

##### A. For Chrome / Chromium-based Browsers

1.  **Open Extensions:** Navigate to `chrome://extensions/`.
2.  **Enable Developer Mode:** Toggle the **"Developer mode"** switch to **ON**.
3.  **Load Extension:** Click the **"Load unpacked"** button.
4.  **Select Folder:** In the file dialog, navigate to the project and **select the folder: `frontend`**.

##### B. For Mozilla Firefox

1.  **Open Debugging:** Open Firefox and navigate to `about:debugging#/runtime/this-firefox`.
2.  **Load Add-on:** Click the **"Load Temporary Add-on..."** button.
3.  **Select File:** Navigate to the **`frontend`** folder. You must select **any file** inside this folder, such as the **`manifest.json`** file.
4.  **Verification:** The extension will be loaded and its icon will appear in your toolbar. (Note: Firefox unloads temporary add-ons when the browser is closed).

#### STEP 3: System Usage and Verification

1.  **Prerequisite Check:** Ensure the Python server from **STEP 1** is running.
2.  **Open Target URL:** Navigate to any website in your browser.
3.  **Click Extension Icon:** Click the **Phishing Detector** icon in your browser's toolbar.
4.  **Analyze:** Click the **"Analyze"** button. The extension sends the URL to the API, and the UI dynamically updates with the **Final Verdict** and the three individual voting results.

---

