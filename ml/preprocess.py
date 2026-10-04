import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd


def clean_column_name(name):
    return (
        str(name)
        .strip()
        .replace("/", "_per_")
        .replace(" ", "_")
        .replace("-", "_")
        .replace(".", "_")
    )


def preprocess(input_file, output_file, report_file, chunksize=100000):

    input_file = Path(input_file)
    output_file = Path(output_file)
    report_file = Path(report_file)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.parent.mkdir(parents=True, exist_ok=True)

    total_rows = 0
    rows_after_cleaning = 0
    duplicate_rows = 0
    missing_label_rows = 0
    infinite_values = 0

    label_counts = {}

    first_chunk = True

    print("\n========================================")
    print("   SENTINELAI DATA PREPROCESSING")
    print("========================================\n")

    print(f"Input : {input_file}")
    print(f"Output: {output_file}\n")

    for chunk_number, df in enumerate(
        pd.read_csv(
            input_file,
            chunksize=chunksize,
            low_memory=False
        ),
        start=1
    ):

        print(f"Processing chunk {chunk_number}...")

        total_rows += len(df)

        # --------------------------------------------------
        # 1. Clean column names
        # --------------------------------------------------

        df.columns = [
            clean_column_name(column)
            for column in df.columns
        ]

        # --------------------------------------------------
        # 2. Remove leading/trailing spaces
        # --------------------------------------------------

        for column in df.select_dtypes(
            include=["object", "string"]
        ).columns:

            df[column] = (
                df[column]
                .astype("string")
                .str.strip()
            )

        # --------------------------------------------------
        # 3. Check Label column
        # --------------------------------------------------

        if "Label" not in df.columns:
            raise ValueError(
                "Label column was not found in the dataset."
            )

        # --------------------------------------------------
        # 4. Replace infinity values
        # --------------------------------------------------

        numeric_columns = df.select_dtypes(
            include=[np.number]
        ).columns

        if len(numeric_columns) > 0:

            infinity_mask = np.isinf(
                df[numeric_columns].to_numpy()
            )

            infinite_values += int(
                infinity_mask.sum()
            )

            df[numeric_columns] = (
                df[numeric_columns]
                .replace([np.inf, -np.inf], np.nan)
            )

        # --------------------------------------------------
        # 5. Remove rows without labels
        # --------------------------------------------------

        missing_labels = df["Label"].isna().sum()

        missing_label_rows += int(
            missing_labels
        )

        df = df.dropna(
            subset=["Label"]
        )

        # --------------------------------------------------
        # 6. Clean labels
        # --------------------------------------------------

        df["Label"] = (
            df["Label"]
            .astype(str)
            .str.strip()
        )

        # --------------------------------------------------
        # 7. Remove duplicate rows
        # --------------------------------------------------

        before_duplicates = len(df)

        df = df.drop_duplicates()

        duplicate_rows += (
            before_duplicates - len(df)
        )

        # --------------------------------------------------
        # 8. Fill numeric missing values
        # --------------------------------------------------

        numeric_columns = df.select_dtypes(
            include=[np.number]
        ).columns

        if len(numeric_columns) > 0:

            medians = df[numeric_columns].median()

            df[numeric_columns] = (
                df[numeric_columns]
                .fillna(medians)
            )

        # --------------------------------------------------
        # 9. Fill remaining text missing values
        # --------------------------------------------------

        text_columns = df.select_dtypes(
            include=["object", "string"]
        ).columns

        for column in text_columns:

            df[column] = (
                df[column]
                .fillna("UNKNOWN")
            )

        # --------------------------------------------------
        # 10. Count labels
        # --------------------------------------------------

        counts = df["Label"].value_counts()

        for label, count in counts.items():

            label = str(label)

            label_counts[label] = (
                label_counts.get(label, 0)
                + int(count)
            )

        rows_after_cleaning += len(df)

        # --------------------------------------------------
        # 11. Save processed chunk
        # --------------------------------------------------

        df.to_csv(
            output_file,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False
        )

        first_chunk = False

        print(
            f"   Rows kept: {len(df):,}"
        )

    # ------------------------------------------------------
    # Create quality report
    # ------------------------------------------------------

    report = {

        "dataset": "CSE-CIC-IDS2018",

        "input_file": str(input_file),

        "output_file": str(output_file),

        "total_input_rows": total_rows,

        "rows_after_cleaning": rows_after_cleaning,

        "duplicate_rows_removed": duplicate_rows,

        "rows_with_missing_label_removed":
            missing_label_rows,

        "infinite_values_replaced":
            infinite_values,

        "label_distribution":
            dict(
                sorted(
                    label_counts.items(),
                    key=lambda item: item[1],
                    reverse=True
                )
            )
    }

    with open(
        report_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print("\n========================================")
    print("       PREPROCESSING COMPLETE")
    print("========================================")

    print(
        f"\nOriginal rows : {total_rows:,}"
    )

    print(
        f"Cleaned rows  : {rows_after_cleaning:,}"
    )

    print(
        f"Duplicates removed : {duplicate_rows:,}"
    )

    print(
        f"Missing labels removed : "
        f"{missing_label_rows:,}"
    )

    print(
        f"Infinite values replaced : "
        f"{infinite_values:,}"
    )

    print("\nLabel distribution:")

    for label, count in sorted(
        label_counts.items(),
        key=lambda item: item[1],
        reverse=True
    ):

        print(
            f"  {label}: {count:,}"
        )

    print(
        f"\nQuality report saved to:"
        f"\n{report_file}"
    )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="SentinelAI dataset preprocessing"
    )

    parser.add_argument(
        "--input",
        required=True
    )

    parser.add_argument(
        "--output",
        required=True
    )

    parser.add_argument(
        "--report",
        required=True
    )

    args = parser.parse_args()

    preprocess(
        args.input,
        args.output,
        args.report
    )