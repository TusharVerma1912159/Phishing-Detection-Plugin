# 🛡️ Phishing Detector: Three-Layer Stacking Ensemble and API Service

## 1. Project Overview

This project implements a highly robust, multi-layer URL classification system designed to detect phishing attempts with high confidence. The architecture combines a sophisticated **Stacked Generalization Ensemble** (local ML) with real-time verification against **External Threat Intelligence** APIs (Google Safe Browsing and VirusTotal). The final decision is a **Majority Vote (2-out-of-3)** across these three independent security checks.

The system operates as two interconnected components:

1.  **Backend (Python/Flask):** A local HTTP API service (`api.py`) that handles URL feature extraction, runs the Machine Learning model, queries external APIs, and returns a unified JSON verdict.
2.  **Frontend (`/frontend` folder):** A user-friendly browser extension (Manifest V3) that captures the current tab's URL and communicates with the local API for instant analysis, displaying the majority verdict and individual component scores.

---

## 2. Technical Architecture: Stacking Ensemble & Majority Vote

The central strength of this project lies in its ability to fuse predictions from multiple, diverse sources, significantly improving reliability and reducing the chance of a false positive or false negative from any single source.

### 2.1 The Stacking Ensemble (Local ML Model)

The local machine learning component utilizes **Stacked Generalization (Stacking)**, an advanced ensemble method. This technique trains multiple Base Learners (Level-0) and then uses their predictions as input for a single Meta-Learner (Level-1), which learns how to optimally combine their outputs. This strategy leverages the strengths of diverse algorithms while compensating for their individual weaknesses.



| Component Type | Specific Algorithm | Library | Role and Rationale |
| :--- | :--- | :--- | :--- |
| **Meta-Learner (Level-1)** | **Logistic Regression** | `scikit-learn` | Acts as the final fusion model. It is trained on the out-of-fold predictions of the Base Learners, making it highly robust to overfitting and excellent for combining probabilities. |
| **Base Learner 1 (Level-0)** | **XGBoost** | `xgboost` | Excellent for tabular data, provides fast, highly accurate predictions via optimized gradient boosting. |
| **Base Learner 2 (Level-0)** | **LightGBM** | `lightgbm` | Known for efficiency and speed, particularly effective on large datasets. |
| **Base Learner 3 (Level-0)** | **CatBoost** | `catboost` | Specifically chosen for its superior handling of raw categorical features (though our feature set is mostly numeric), ensuring robustness against potential data shifts. |
| **Feature Preprocessing** | **StandardScaler** | `scikit-learn` | Ensures all 48 URL features are standardized (zero mean, unit variance) before model input, preventing high-magnitude features from dominating the model training. |

### 2.2 External Threat Intelligence Fusion

The final outcome is determined by the **Majority Vote** across the three core indicators:

| Source | Check Type | Outcome Values |
| :--- | :--- | :--- |
| **Phisher Model** | Local ML (Stacking Ensemble) | `Phishing` / `Legitimate` |
| **Google Safe Browsing (GSB)** | External API Check | `Phishing` / `Legitimate` / `Unknown` |
| **VirusTotal (VT)** | External API Check | `Phishing` / `Legitimate` / `Unknown` |

The `api.py` service performs this fusion logic, returning a high-level final verdict (`Phishing`, `Legitimate`, or `Suspicious`).

---

## 3. Environment & Setup

### 3.1 Comprehensive Python Dependencies (`requirements.txt`)

For guaranteed reproducibility, all Python dependencies, including all specialized ML libraries, are listed in the `requirements.txt` file.

**File: `requirements.txt`**
```text
# =========================================================================
# PHISHING DETECTOR ENVIRONMENT REQUIREMENTS
# All necessary packages for the Stacking Ensemble and Flask API.
# =========================================================================

# CORE DATA SCIENCE & UTILITIES
joblib          # For saving/loading models (PKL files) and scalers
numpy           # Numerical computing base
pandas          # Data manipulation and feature construction
configparser    # To securely read API keys from config.ini

# SCALING, STACKING & META-LEARNER
scikit-learn    # Includes StackingClassifier, StandardScaler, and LogisticRegression (meta-learner)

# BASE LEARNERS (Level-0 Models)
xgboost
lightgbm
catboost        

# API & NETWORK SERVICES
Flask           # The micro-web framework for the API
requests        # For making external HTTP requests (GSB, VT)
tldextract      # For robust extraction of eTLD+1 (registered domain)
