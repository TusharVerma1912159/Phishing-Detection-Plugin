# train_model_full.py 
# -----------------------------------------------------------------------------
# Purpose:
#   Train a stacking (ensemble) classifier for phishing detection using the
#   full (numeric) feature set.
#   Saves three artifacts:
#     - phishing_stacking_model.pkl : the trained StackingClassifier
#     - scaler.pkl                  : StandardScaler fit on the training data
#     - feature_names.pkl           : the scaler's input feature names (order)
#
# -----------------------------------------------------------------------------

import os, joblib, warnings    # stdlib + joblib + warnings for saving model and silencing noise
warnings.filterwarnings("ignore")  # keep training output clean (suppress warnings)
import numpy as np, pandas as pd    # numerical + dataframe libraries

from sklearn.model_selection import train_test_split    # for splitting into train/test sets
from sklearn.preprocessing import StandardScaler         # for standardizing numeric features
from sklearn.metrics import classification_report, accuracy_score  # basic metrics for evaluation
from sklearn.ensemble import StackingClassifier   # main stacking ensemble class
from sklearn.linear_model import LogisticRegression      # meta-learner (top-level classifier)
 
def build_base_learners(random_state=42):
    """
    Build the base learners (level-0 models) for stacking.

    Tries to include gradient-boosting libraries:
      - XGBoost
      - LightGBM
      - CatBoost

    Returns:
        list of (name, estimator) tuples for StackingClassifier.
    """
    learners = []    # list to collect (name, estimator) pairs

    try:
        from xgboost import XGBClassifier
        learners.append(("xgb", XGBClassifier(
            n_estimators=300, max_depth=6, learning_rate=0.1,
            subsample=0.9, colsample_bytree=0.9, reg_lambda=1.0,
            random_state=random_state, n_jobs=-1, tree_method="hist")))
    except Exception:
        from sklearn.ensemble import GradientBoostingClassifier
        learners.append(("gb", GradientBoostingClassifier(random_state=random_state)))

    
    try:
        from lightgbm import LGBMClassifier
        learners.append(("lgb", LGBMClassifier(
            n_estimators=400, learning_rate=0.06, subsample=0.9,
            colsample_bytree=0.9, reg_lambda=1.0, random_state=random_state, n_jobs=-1)))
    except Exception:
        from sklearn.ensemble import ExtraTreesClassifier
        learners.append(("et", ExtraTreesClassifier(n_estimators=400, random_state=random_state, n_jobs=-1)))

    
    try:
        from catboost import CatBoostClassifier
        learners.append(("cat", CatBoostClassifier(
            iterations=400, depth=6, learning_rate=0.08, l2_leaf_reg=2.0,
            random_state=random_state, verbose=False)))
    # Only used for backup , not used in our model
    except Exception:
        from sklearn.ensemble import RandomForestClassifier
        learners.append(("rf", RandomForestClassifier(n_estimators=400, random_state=random_state, n_jobs=-1)))

    return learners


def detect_label_column(df: pd.DataFrame) -> str:
    """
    Automatically detect the label/target column in a dataset.

    Strategy:
      1) Check a list of common label names (case-insensitive).
      2) If not found, look for any binary column (0/1).

    Args:
        df: DataFrame loaded from the CSV.

    Returns:
        The exact column name to use as the label.

    Raises:
        ValueError if no suitable label column is found.
    """
    candidates = ["label","labels","class","class_label","classlabel","target",
                  "y","is_phishing","phishing","malicious","result","status","CLASS_LABEL"]

    # Build lowercase→original map to do case-insensitive detection.
    lower_map = {c.lower(): c for c in df.columns}

    # 1) Try known names
    for cand in candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]

    # 2) Heuristic fallback: binary column with a label-ish name
    for c in df.columns:
        vals = set(pd.Series(df[c]).dropna().unique().tolist()[:10])  # inspect a small sample of unique vals
        if vals.issubset({0,1}) and any(k in c.lower() for k in ["label","class","phish","target"]):
            return c

    # Nothing matched
    raise ValueError("Could not find label column (e.g., CLASS_LABEL, label).")


def main():
    """
    Main training routine:
      - Load CSV (path via DATA_PATH env var or default filename).
      - Detect label column, drop known non-feature ID/index columns.
      - Keep numeric features only, sanitize NaNs/Infs.
      - Train/test split with stratification.
      - Scale features on full set.
      - Build base learners + meta-learner (stacking with passthrough).
      - Fit, evaluate, and persist artifacts (model, scaler, feature order).
    """
    # 1) Locate the dataset
    DATA_PATH = os.getenv("DATA_PATH", "Phishing_Legitimate_full.csv")
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at: {DATA_PATH}")

    # 2) Load CSV into DataFrame
    df = pd.read_csv(DATA_PATH)

    # 3) Find the label column automatically
    label_col = detect_label_column(df)

    # 4) Drop common non-feature columns (IDs, unnamed indices)
    drop_cols = [c for c in ["id","Id","ID","index","Index","Unnamed: 0"] if c in df.columns]

    # 5) Split into target y and features X
    y = df[label_col].astype(int).values
    X = df.drop(columns=[label_col] + drop_cols, errors="ignore")

    # 6) Keep numeric columns only (model expects numeric engineered features)
    num_cols = [c for c in X.columns if np.issubdtype(X[c].dtype, np.number)]
    X = X[num_cols].copy()

    # 7) Replace infinities and NaNs with 0.0 to ensure finite inputs for scaler/model
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    # Informational printouts for transparency
    print(f"\nUsing {len(num_cols)} numeric features.")
    print("First 8:", num_cols[:8])

    # 8) Train/test split with stratification to preserve class balance
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 9) Standardize features on the full set 
    #    Fit scaler on training data only; transform both train and test.
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # 10) Build base learners and define meta-learner (Logistic Regression)
    base = build_base_learners(random_state=42)
    meta = LogisticRegression(max_iter=300, solver="lbfgs")

    # 11) Create the stacking classifier (with passthrough so meta gets original features)
    #     Use cv=5 for meta-learner training on out-of-fold predictions.
    try:
        model = StackingClassifier(estimators=base, final_estimator=meta, cv=5, passthrough=True, n_jobs=-1)
    except TypeError:
        # Older scikit-learn versions may not support n_jobs in StackingClassifier
        model = StackingClassifier(estimators=base, final_estimator=meta, cv=5, passthrough=True)

    # 12) Fit the stacking model
    model.fit(X_train_s, y_train)

    # 13) Evaluate on the held-out test set
    y_pred = model.predict(X_test_s)
    print("\nAccuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred, digits=4))

    # 14) Persist artifacts for inference:
    #     - model: used to predict labels
    #     - scaler: used to transform features in the exact same way as training
    #     - feature_names: canonical order of columns the scaler expects
    joblib.dump(model, "phishing_stacking_model.pkl")
    joblib.dump(scaler, "scaler.pkl")

    # Save the *exact* feature order the scaler was fit on.
    # This list must be used at inference time to build the vector in the
    # same order before calling scaler.transform (prevents mismatches).
    joblib.dump(list(scaler.feature_names_in_), "feature_names.pkl")

    print("\nSaved: phishing_stacking_model.pkl, scaler.pkl, feature_names.pkl (full set, aligned)")


if __name__ == "__main__":
    # Entry point for CLI execution
    main()
