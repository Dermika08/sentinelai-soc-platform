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
)


MODEL_FILE = Path(
    "models/attack_classifier.joblib"
)

OUTPUT_FILE = Path(
    "reports/attack_unseen_evaluation.json"
)

# We will test on a completely different capture day.
INPUT_FILE = Path(
    "data/raw/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
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


LABEL_MAP = {
    "Bot": "Bot",

    "DoS attacks-Hulk": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",

    "Infilteration": "Infiltration",
}


def main():

    print("\n========================================")
    print(" SENTINELAI UNSEEN ATTACK EVALUATION")
    print("========================================")

    print("\nLoading trained model...")

    saved = joblib.load(
        MODEL_FILE
    )

    model = saved["model"]
    features = saved["features"]
    classes = saved["classes"]

    print(
        f"Model classes: {classes}"
    )

    y_true = []
    y_pred = []

    total_rows = 0
    usable_rows = 0

    print(
        "\nReading unseen dataset..."
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

        # Clean column names exactly like
        # the training pipeline.
        df.columns = [
            str(column)
            .strip()
            .replace("/", "_per_")
            .replace(" ", "_")
            .replace("-", "_")
            .replace(".", "_")
            for column in df.columns
        ]

        # Map raw labels.
        df["Attack_Family"] = (
            df["Label"]
            .map(LABEL_MAP)
        )

        # Remove classes that this model
        # was not trained to classify.
        df = df[
            df["Attack_Family"].isin(
                classes
            )
        ].copy()

        if len(df) == 0:
            continue

        X = df[
            features
        ].copy()

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

        predictions = model.predict(X)

        y_true.extend(
            df["Attack_Family"].tolist()
        )

        y_pred.extend(
            predictions.tolist()
        )

        usable_rows += len(df)

    print(
        "\n========================================"
    )

    print(
        "      UNSEEN-DAY RESULTS"
    )

    print(
        "========================================"
    )

    print(
        f"\nTotal rows read : {total_rows:,}"
    )

    print(
        f"Rows evaluated  : {usable_rows:,}"
    )

    if usable_rows == 0:

        print(
            "\nNo compatible attack classes "
            "were found in this dataset."
        )

        return

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    precision = precision_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0
    )

    weighted_f1 = f1_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0
    )

    macro_f1 = f1_score(
        y_true,
        y_pred,
        average="macro",
        zero_division=0
    )

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=classes
    )

    report = classification_report(
        y_true,
        y_pred,
        labels=classes,
        target_names=classes,
        zero_division=0
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

    print(matrix)

    print(
        "\nClassification Report:"
    )

    print(report)

    # Save report.
    output = {

        "dataset":
            str(INPUT_FILE),

        "rows_read":
            total_rows,

        "rows_evaluated":
            usable_rows,

        "classes":
            classes,

        "accuracy":
            float(accuracy),

        "precision":
            float(precision),

        "recall":
            float(recall),

        "weighted_f1":
            float(weighted_f1),

        "macro_f1":
            float(macro_f1),

        "confusion_matrix":
            matrix.tolist(),

        "classification_report":
            report,
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=4
        )

    print(
        f"\nEvaluation report saved:"
        f"\n{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()