import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


INPUT_FILE = Path(
    "data/raw/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv"
)

MODEL_FILE = Path(
    "models/bot_detector.joblib"
)

REPORT_FILE = Path(
    "reports/unseen_day_evaluation.json"
)

CHUNK_SIZE = 100_000


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
    print("    SENTINELAI UNSEEN-DAY EVALUATION")
    print("========================================\n")

    print("Loading trained model...")

    bundle = joblib.load(
        MODEL_FILE
    )

    model = bundle["model"]
    scaler = bundle["scaler"]
    feature_columns = bundle["features"]
    model_type = bundle["model_type"]

    print(
        f"Model: {model_type}"
    )

    print(
        f"Features expected: "
        f"{len(feature_columns)}"
    )

    all_predictions = []
    all_probabilities = []
    all_actual = []

    total_rows = 0

    print(
        "\nReading unseen dataset in chunks...\n"
    )

    for chunk_number, df in enumerate(
        pd.read_csv(
            INPUT_FILE,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ),
        start=1
    ):

        print(
            f"Evaluating chunk {chunk_number}..."
        )

        total_rows += len(df)

        # -----------------------------------------
        # Clean column names exactly as before
        # -----------------------------------------

        df.columns = [
            str(column)
            .strip()
            .replace("/", "_per_")
            .replace(" ", "_")
            .replace("-", "_")
            .replace(".", "_")
            for column in df.columns
        ]

        # -----------------------------------------
        # Convert target
        # -----------------------------------------

        y = (
            df["Label"]
            .astype(str)
            .str.strip()
            .map({
                "Benign": 0,
                "Bot": 1
            })
        )

        valid_rows = y.notna()

        df = df.loc[
            valid_rows
        ].copy()

        y = y.loc[
            valid_rows
        ]

        # -----------------------------------------
        # Select EXACT training features
        # -----------------------------------------

        missing_features = [
            feature
            for feature in feature_columns
            if feature not in df.columns
        ]

        if missing_features:

            raise ValueError(
                "Missing features in unseen dataset: "
                + str(missing_features)
            )

        X = df[
            feature_columns
        ].copy()

        # -----------------------------------------
        # Numeric conversion
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

        # -----------------------------------------
        # Prediction
        # -----------------------------------------

        if model_type == "Logistic Regression":

            X_model = scaler.transform(
                X
            )

        else:

            X_model = X

        predictions = model.predict(
            X_model
        )

        probabilities = model.predict_proba(
            X_model
        )[:, 1]

        all_predictions.extend(
            predictions.tolist()
        )

        all_probabilities.extend(
            probabilities.tolist()
        )

        all_actual.extend(
            y.astype(int).tolist()
        )

    # ---------------------------------------------
    # Final evaluation
    # ---------------------------------------------

    y_true = np.array(
        all_actual
    )

    y_pred = np.array(
        all_predictions
    )

    y_prob = np.array(
        all_probabilities
    )

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0
    )

    roc_auc = roc_auc_score(
        y_true,
        y_prob
    )

    matrix = confusion_matrix(
        y_true,
        y_pred
    )

    print(
        "\n========================================"
    )

    print(
        "       UNSEEN-DAY RESULTS"
    )

    print(
        "========================================"
    )

    print(
        f"\nRows evaluated: {total_rows:,}"
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

    print(
        "\nConfusion Matrix:"
    )

    print(matrix)

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_true,
            y_pred,
            target_names=[
                "Benign",
                "Bot"
            ],
            zero_division=0
        )
    )

    # ---------------------------------------------
    # Save report
    # ---------------------------------------------

    report = {

        "evaluation_type":
            "unseen_day",

        "training_dataset":
            "Friday-02-03-2018",

        "evaluation_dataset":
            "Friday-16-02-2018",

        "model":
            model_type,

        "rows_evaluated":
            int(total_rows),

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
            matrix.tolist()
    }

    REPORT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print(
        f"\nReport saved to:"
        f"\n{REPORT_FILE}"
    )


if __name__ == "__main__":
    main()