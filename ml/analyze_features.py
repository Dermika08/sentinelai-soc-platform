import json
from pathlib import Path

import numpy as np
import pandas as pd


INPUT_FILE = Path(
    "data/processed/friday_02_03_2018_clean.csv"
)

OUTPUT_FILE = Path(
    "data/processed/feature_analysis.json"
)

CHUNK_SIZE = 100_000


def main():

    print("\n========================================")
    print("      SENTINELAI FEATURE ANALYSIS")
    print("========================================\n")

    print("Reading dataset in chunks...\n")

    total_rows = 0
    label_counts = {}
    numeric_columns = None

    min_values = {}
    max_values = {}
    zero_counts = {}
    sum_values = {}
    sum_squares = {}

    for chunk_number, df in enumerate(
        pd.read_csv(
            INPUT_FILE,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ),
        start=1
    ):

        print(f"Analyzing chunk {chunk_number}...")

        total_rows += len(df)

        # -------------------------------
        # Label distribution
        # -------------------------------

        labels = df["Label"].value_counts()

        for label, count in labels.items():

            label = str(label)

            label_counts[label] = (
                label_counts.get(label, 0)
                + int(count)
            )

        # -------------------------------
        # Select numeric features
        # -------------------------------

        current_numeric = df.select_dtypes(
            include=[np.number]
        ).columns.tolist()

        if numeric_columns is None:

            numeric_columns = current_numeric

            for column in numeric_columns:

                min_values[column] = np.inf
                max_values[column] = -np.inf
                zero_counts[column] = 0
                sum_values[column] = 0.0
                sum_squares[column] = 0.0

        # -------------------------------
        # Statistics
        # -------------------------------

        for column in numeric_columns:

            values = pd.to_numeric(
                df[column],
                errors="coerce"
            ).dropna()

            if len(values) == 0:
                continue

            min_values[column] = min(
                min_values[column],
                float(values.min())
            )

            max_values[column] = max(
                max_values[column],
                float(values.max())
            )

            zero_counts[column] += int(
                (values == 0).sum()
            )

            sum_values[column] += float(
                values.sum()
            )

            sum_squares[column] += float(
                (values ** 2).sum()
            )

    # ------------------------------------
    # Calculate variance
    # ------------------------------------

    feature_statistics = {}

    for column in numeric_columns:

        mean = sum_values[column] / total_rows

        variance = (
            sum_squares[column] / total_rows
        ) - (mean ** 2)

        if variance < 0:
            variance = 0

        feature_statistics[column] = {

            "min": min_values[column],

            "max": max_values[column],

            "mean": mean,

            "variance": variance,

            "zero_count": zero_counts[column],

            "zero_percentage":
                (zero_counts[column] / total_rows) * 100
        }

    # ------------------------------------
    # Identify constant features
    # ------------------------------------

    constant_features = []

    for column, stats in feature_statistics.items():

        if stats["variance"] == 0:

            constant_features.append(column)

    # ------------------------------------
    # Identify near-zero variance
    # ------------------------------------

    near_zero_features = []

    for column, stats in feature_statistics.items():

        if (
            stats["zero_percentage"] > 99.9
            or stats["variance"] < 1e-10
        ):

            near_zero_features.append(column)

    # ------------------------------------
    # Create report
    # ------------------------------------

    report = {

        "dataset":
            "CSE-CIC-IDS2018",

        "total_rows":
            total_rows,

        "numeric_feature_count":
            len(numeric_columns),

        "numeric_features":
            numeric_columns,

        "label_distribution":
            label_counts,

        "constant_features":
            constant_features,

        "near_zero_variance_features":
            near_zero_features,

        "feature_statistics":
            feature_statistics
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print("\n========================================")
    print("        ANALYSIS COMPLETE")
    print("========================================")

    print(
        f"\nTotal rows: {total_rows:,}"
    )

    print(
        f"Numeric features: "
        f"{len(numeric_columns)}"
    )

    print("\nLabel distribution:")

    for label, count in sorted(
        label_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):

        percentage = (
            count / total_rows
        ) * 100

        print(
            f"  {label}: "
            f"{count:,} "
            f"({percentage:.2f}%)"
        )

    print("\nConstant features:")

    if constant_features:

        for feature in constant_features:
            print(f"  - {feature}")

    else:

        print("  None")

    print("\nNear-zero variance features:")

    if near_zero_features:

        for feature in near_zero_features:
            print(f"  - {feature}")

    else:

        print("  None")

    print(
        f"\nReport saved to:\n"
        f"{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()