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


# We intentionally exclude Web Attack for now.
# There are only 566 samples, which is not enough
# for a reliable general classifier.
TARGET_CLASSES = [
    "Bot",
    "DoS",
    "Infiltration",
]


def main():

    print("\n========================================")
    print("     SENTINELAI ATTACK CLASSIFIER")
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
    # Keep only attack families used here
    # -----------------------------------------

    df = df[
        df["Attack_Family"].isin(
            TARGET_CLASSES
        )
    ].copy()

    print(
        f"Malicious rows used: "
        f"{len(df):,}"
    )

    print(
        "\nAttack distribution:"
    )

    print(
        df["Attack_Family"]
        .value_counts()
        .to_string()
    )

    # -----------------------------------------
    # Remove unnecessary columns
    # -----------------------------------------

    excluded_columns = {
        "Label",
        "Attack_Family",
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

    y = df[
        "Attack_Family"
    ]

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
        f"\nFeatures used: "
        f"{len(feature_columns)}"
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
        f"Training rows: "
        f"{len(X_train):,}"
    )

    print(
        f"Testing rows : "
        f"{len(X_test):,}"
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
    # Predictions
    # -----------------------------------------

    print(
        "\nGenerating predictions..."
    )

    predictions = model.predict(
        X_test
    )

    # -----------------------------------------
    # Metrics
    # -----------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    weighted_f1 = f1_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    macro_f1 = f1_score(
        y_test,
        predictions,
        average="macro",
        zero_division=0
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
        labels=TARGET_CLASSES
    )

    report_text = classification_report(
        y_test,
        predictions,
        labels=TARGET_CLASSES,
        target_names=TARGET_CLASSES,
        zero_division=0
    )

    # -----------------------------------------
    # Results
    # -----------------------------------------

    print(
        "\n========================================"
    )

    print(
        "     ATTACK CLASSIFIER RESULTS"
    )

    print(
        "========================================"
    )

    print(
        f"\nAccuracy     : {accuracy:.4f}"
    )

    print(
        f"Precision    : {precision:.4f}"
    )

    print(
        f"Recall       : {recall:.4f}"
    )

    print(
        f"Weighted F1  : {weighted_f1:.4f}"
    )

    print(
        f"Macro F1     : {macro_f1:.4f}"
    )

    print(
        "\nConfusion Matrix:"
    )

    print(
        matrix
    )

    print(
        "\nClassification Report:"
    )

    print(
        report_text
    )

    # -----------------------------------------
    # Feature importance
    # -----------------------------------------

    importance = pd.DataFrame({
        "feature": feature_columns,
        "importance":
            model.feature_importances_
    })

    importance = importance.sort_values(
        "importance",
        ascending=False
    )

    print(
        "\nTop 15 important features:"
    )

    print(
        importance
        .head(15)
        .to_string(index=False)
    )

    # -----------------------------------------
    # Save model
    # -----------------------------------------

    model_path = (
        MODEL_DIR /
        "attack_classifier.joblib"
    )

    joblib.dump(
        {
            "model": model,
            "features": feature_columns,
            "classes": TARGET_CLASSES
        },
        model_path
    )

    # -----------------------------------------
    # Save feature importance
    # -----------------------------------------

    importance_path = (
        REPORT_DIR /
        "attack_feature_importance.csv"
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
            "Malicious attack family classification",

        "classes":
            TARGET_CLASSES,

        "training_rows":
            int(len(X_train)),

        "testing_rows":
            int(len(X_test)),

        "features":
            feature_columns,

        "accuracy":
            float(accuracy),

        "weighted_precision":
            float(precision),

        "weighted_recall":
            float(recall),

        "weighted_f1":
            float(weighted_f1),

        "macro_f1":
            float(macro_f1),

        "confusion_matrix":
            matrix.tolist(),

        "classification_report":
            report_text,

        "top_features":
            importance.head(15).to_dict(
                orient="records"
            )
    }

    report_path = (
        REPORT_DIR /
        "attack_classifier_evaluation.json"
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