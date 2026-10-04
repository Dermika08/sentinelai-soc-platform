import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
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


INPUT_FILE = Path(
    "data/processed/sentinelai_multiclass.csv"
)

MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


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


def main():

    print("\n========================================")
    print("       SENTINELAI THREAT DETECTOR")
    print("========================================")

    print("\nLoading unified dataset...")

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False
    )

    print(
        f"Rows loaded: {len(df):,}"
    )

    # -----------------------------------------
    # Create binary target
    # -----------------------------------------

    df["Threat"] = (
        df["Attack_Family"]
        .apply(
            lambda x:
            0 if x == "Benign" else 1
        )
    )

    # -----------------------------------------
    # Select features
    # -----------------------------------------

    excluded_columns = {
        "Label",
        "Attack_Family",
        "Threat",
        "Timestamp",
    }

    excluded_columns.update(
        CONSTANT_FEATURES
    )

    feature_columns = [
        column
        for column in df.columns
        if column not in excluded_columns
    ]

    X = df[
        feature_columns
    ].copy()

    y = df["Threat"]

    # -----------------------------------------
    # Numeric cleanup
    # -----------------------------------------

    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    X = X.fillna(
        X.median()
    )

    print(
        f"Features used: {len(feature_columns)}"
    )

    print(
        "\nThreat distribution:"
    )

    print(
        y.map({
            0: "Benign",
            1: "Malicious"
        }).value_counts().to_string()
    )

    # -----------------------------------------
    # Train/test split
    # -----------------------------------------

    print(
        "\nCreating stratified split..."
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

    # -----------------------------------------
    # Train Random Forest
    # -----------------------------------------

    print(
        "\nTraining Random Forest..."
    )

    model = RandomForestClassifier(
        n_estimators=150,
        class_weight="balanced",
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )

    model.fit(
        X_train,
        y_train
    )

    # -----------------------------------------
    # Evaluate
    # -----------------------------------------

    print(
        "\nGenerating predictions..."
    )

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
        "\n========================================"
    )

    print(
        "       THREAT DETECTOR RESULTS"
    )

    print(
        "========================================"
    )

    print(
        f"\nAccuracy : {accuracy:.4f}"
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

    print(
        "\nConfusion Matrix:"
    )

    print(matrix)

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Benign",
                "Malicious"
            ],
            zero_division=0
        )
    )

    # -----------------------------------------
    # Feature importance
    # -----------------------------------------

    importance = pd.DataFrame({
        "feature": feature_columns,
        "importance": model.feature_importances_
    })

    importance = importance.sort_values(
        "importance",
        ascending=False
    )

    print(
        "\nTop 15 important features:"
    )

    print(
        importance.head(15).to_string(
            index=False
        )
    )

    # -----------------------------------------
    # Save model
    # -----------------------------------------

    model_path = (
        MODEL_DIR /
        "threat_detector.joblib"
    )

    joblib.dump(
        {
            "model": model,
            "features": feature_columns
        },
        model_path
    )

    # -----------------------------------------
    # Save feature importance
    # -----------------------------------------

    importance_path = (
        REPORT_DIR /
        "threat_feature_importance.csv"
    )

    importance.to_csv(
        importance_path,
        index=False
    )

    # -----------------------------------------
    # Save evaluation report
    # -----------------------------------------

    report = {

        "model":
            "Random Forest",

        "task":
            "Benign vs Malicious",

        "training_rows":
            int(len(X_train)),

        "testing_rows":
            int(len(X_test)),

        "features":
            feature_columns,

        "accuracy":
            float(accuracy),

        "precision":
            float(precision),

        "recall":
            float(recall),

        "f1":
            float(f1),

        "roc_auc":
            float(roc_auc),

        "confusion_matrix":
            matrix.tolist(),

        "top_features":
            importance.head(15).to_dict(
                orient="records"
            )
    }

    report_path = (
        REPORT_DIR /
        "threat_detector_evaluation.json"
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
        f"\nModel saved:"
        f"\n{model_path}"
    )

    print(
        f"\nFeature importance saved:"
        f"\n{importance_path}"
    )

    print(
        f"\nEvaluation report saved:"
        f"\n{report_path}"
    )


if __name__ == "__main__":
    main()