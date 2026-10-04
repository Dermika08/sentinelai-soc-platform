import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


INPUT_FILE = Path(
    "data/processed/friday_02_03_2018_clean.csv"
)

MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# Features found to be constant during our analysis.
CONSTANT_FEATURES = [
    "Flow_Duration",
    "Bwd_PSH_Flags",
    "Fwd_URG_Flags",
    "Bwd_URG_Flags",
    "CWE_Flag_Count",
    "Fwd_Byts_per_b_Avg",
    "Fwd_Pkts_per_b_Avg",
    "Fwd_Blk_Rate_Avg",
    "Bwd_Byts_per_b_Avg",
    "Bwd_Pkts_per_b_Avg",
    "Bwd_Blk_Rate_Avg",
]

# We don't use Timestamp as a raw model feature.
DROP_COLUMNS = CONSTANT_FEATURES + [
    "Timestamp",
    "Label",
]


def load_data():

    print("\nLoading dataset...")

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False
    )

    print(
        f"Loaded {len(df):,} rows."
    )

    return df


def prepare_data(df):

    print("\nPreparing features...")

    # Remove unwanted features.
    feature_columns = [
        column
        for column in df.columns
        if column not in DROP_COLUMNS
    ]

    X = df[feature_columns].copy()

    # Convert target.
    y = (
        df["Label"]
        .astype(str)
        .str.strip()
        .map({
            "Benign": 0,
            "Bot": 1
        })
    )

    # Safety check.
    if y.isna().any():

        unknown_labels = (
            df.loc[y.isna(), "Label"]
            .unique()
            .tolist()
        )

        raise ValueError(
            f"Unknown labels found: {unknown_labels}"
        )

    # Make sure everything is numeric.
    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    # Replace any remaining infinity.
    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Fill any unexpected missing values.
    X = X.fillna(
        X.median()
    )

    print(
        f"Features used: {len(feature_columns)}"
    )

    print(
        f"Rows: {len(X):,}"
    )

    return X, y, feature_columns


def evaluate_model(
    name,
    model,
    X_test,
    y_test
):

    predictions = model.predict(
        X_test
    )

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_test,
        probabilities
    )

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print(
        f"\n========== {name} =========="
    )

    print(
        f"Accuracy : {accuracy:.4f}"
    )

    print(
        f"Precision: {precision:.4f}"
    )

    print(
        f"Recall   : {recall:.4f}"
    )

    print(
        f"F1 Score : {f1:.4f}"
    )

    print(
        f"ROC-AUC  : {roc_auc:.4f}"
    )

    print("\nConfusion Matrix:")

    print(matrix)

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Benign",
                "Bot"
            ],
            zero_division=0
        )
    )

    return {
        "model": name,
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "confusion_matrix": matrix.tolist(),
    }


def main():

    print("\n========================================")
    print("       SENTINELAI BOT DETECTOR")
    print("========================================")

    df = load_data()

    X, y, feature_columns = prepare_data(
        df
    )

    # ------------------------------------------------
    # Train / test split
    # ------------------------------------------------

    print(
        "\nCreating stratified train/test split..."
    )

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y
        )
    )

    print(
        f"Training rows: {len(X_train):,}"
    )

    print(
        f"Testing rows : {len(X_test):,}"
    )

    # ------------------------------------------------
    # Logistic Regression
    # ------------------------------------------------

    print(
        "\nTraining Logistic Regression..."
    )

    scaler = StandardScaler()

    X_train_scaled = scaler.fit_transform(
        X_train
    )

    X_test_scaled = scaler.transform(
        X_test
    )

    logistic_model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42
    )

    logistic_model.fit(
        X_train_scaled,
        y_train
    )

    logistic_results = evaluate_model(
        "Logistic Regression",
        logistic_model,
        X_test_scaled,
        y_test
    )

    # ------------------------------------------------
    # Random Forest
    # ------------------------------------------------

    print(
        "\nTraining Random Forest..."
    )

    random_forest = RandomForestClassifier(
        n_estimators=150,
        max_depth=None,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    random_forest.fit(
        X_train,
        y_train
    )

    forest_results = evaluate_model(
        "Random Forest",
        random_forest,
        X_test,
        y_test
    )

    # ------------------------------------------------
    # Select best model by F1
    # ------------------------------------------------

    results = [
        logistic_results,
        forest_results
    ]

    best_result = max(
        results,
        key=lambda item: item["f1"]
    )

    if best_result["model"] == "Random Forest":

        best_model = random_forest

        model_type = "Random Forest"

    else:

        best_model = logistic_model

        model_type = "Logistic Regression"

    # ------------------------------------------------
    # Save best model
    # ------------------------------------------------

    model_path = (
        MODEL_DIR /
        "bot_detector.joblib"
    )

    joblib.dump(
        {
            "model": best_model,
            "scaler": (
                scaler
                if model_type ==
                "Logistic Regression"
                else None
            ),
            "features": feature_columns,
            "model_type": model_type
        },
        model_path
    )

    # ------------------------------------------------
    # Save feature list
    # ------------------------------------------------

    feature_path = (
        MODEL_DIR /
        "feature_list.json"
    )

    with open(
        feature_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            feature_columns,
            file,
            indent=4
        )

    # ------------------------------------------------
    # Save report
    # ------------------------------------------------

    report = {

        "dataset":
            "CSE-CIC-IDS2018",

        "target":
            "Bot vs Benign",

        "training_rows":
            len(X_train),

        "testing_rows":
            len(X_test),

        "features":
            feature_columns,

        "models":
            results,

        "selected_model":
            model_type,

        "selection_metric":
            "F1 score"
    }

    report_path = (
        REPORT_DIR /
        "model_evaluation.json"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print(
        "\n========================================"
    )

    print(
        "       TRAINING COMPLETE"
    )

    print(
        "========================================"
    )

    print(
        f"\nBest model: {model_type}"
    )

    print(
        f"Best F1: {best_result['f1']:.4f}"
    )

    print(
        f"\nModel saved to:"
        f"\n{model_path}"
    )

    print(
        f"\nFeature list saved to:"
        f"\n{feature_path}"
    )

    print(
        f"\nEvaluation report saved to:"
        f"\n{report_path}"
    )


if __name__ == "__main__":
    main()