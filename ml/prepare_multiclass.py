import json
from pathlib import Path

import pandas as pd


RAW_DIR = Path("data/raw")
OUTPUT_DIR = Path("data/processed")

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

OUTPUT_FILE = (
    OUTPUT_DIR /
    "sentinelai_multiclass.csv"
)

REPORT_FILE = (
    OUTPUT_DIR /
    "multiclass_dataset_report.json"
)

# Maximum number of benign samples kept from each dataset.
# We don't need millions of almost-identical benign records.
MAX_BENIGN_PER_FILE = 150_000

CHUNK_SIZE = 100_000


DATASETS = [
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
]


def map_attack_family(label):

    label = str(label).strip()

    if label == "Benign":
        return "Benign"

    if label == "Bot":
        return "Bot"

    if label in [
        "DoS attacks-Hulk",
        "DoS attacks-SlowHTTPTest",
    ]:
        return "DoS"

    if label in [
        "Brute Force -Web",
        "Brute Force -XSS",
        "SQL Injection",
    ]:
        return "Web Attack"

    if label == "Infilteration":
        return "Infiltration"

    return None


def process_file(filename):

    input_path = RAW_DIR / filename

    print("\n========================================")
    print(f"Processing: {filename}")
    print("========================================")

    chunks = []

    benign_kept = 0
    attack_rows = 0
    total_rows = 0
    unknown_rows = 0

    for chunk_number, df in enumerate(
        pd.read_csv(
            input_path,
            chunksize=CHUNK_SIZE,
            low_memory=False
        ),
        start=1
    ):

        print(
            f"Chunk {chunk_number}..."
        )

        total_rows += len(df)

        # Standardize column names.
        df.columns = [
            str(column)
            .strip()
            .replace("/", "_per_")
            .replace(" ", "_")
            .replace("-", "_")
            .replace(".", "_")
            for column in df.columns
        ]

        # Map raw labels to our attack families.
        df["Attack_Family"] = (
            df["Label"]
            .map(map_attack_family)
        )

        unknown = df[
            df["Attack_Family"].isna()
        ]

        unknown_rows += len(unknown)

        df = df[
            df["Attack_Family"].notna()
        ].copy()

        # Separate benign and malicious traffic.
        benign = df[
            df["Attack_Family"] == "Benign"
        ]

        attacks = df[
            df["Attack_Family"] != "Benign"
        ]

        # Keep all attacks.
        if len(attacks) > 0:

            chunks.append(
                attacks
            )

            attack_rows += len(attacks)

        # Limit benign samples.
        remaining = (
            MAX_BENIGN_PER_FILE
            - benign_kept
        )

        if remaining > 0 and len(benign) > 0:

            take = min(
                remaining,
                len(benign)
            )

            benign_sample = (
                benign
                .sample(
                    n=take,
                    random_state=42
                )
            )

            chunks.append(
                benign_sample
            )

            benign_kept += take

    if not chunks:

        return pd.DataFrame(), {
            "total_rows": total_rows,
            "benign_kept": benign_kept,
            "attack_rows": attack_rows,
            "unknown_rows": unknown_rows,
        }

    result = pd.concat(
        chunks,
        ignore_index=True
    )

    return result, {
        "total_rows": total_rows,
        "benign_kept": benign_kept,
        "attack_rows": attack_rows,
        "unknown_rows": unknown_rows,
    }


def main():

    print("\n========================================")
    print("   SENTINELAI MULTI-CLASS DATASET")
    print("========================================")

    all_data = []

    file_reports = {}

    for filename in DATASETS:

        data, report = process_file(
            filename
        )

        if len(data) > 0:

            all_data.append(
                data
            )

        file_reports[
            filename
        ] = report

    print(
        "\nCombining datasets..."
    )

    final_df = pd.concat(
        all_data,
        ignore_index=True
    )

    # Shuffle the final dataset.
    final_df = final_df.sample(
        frac=1,
        random_state=42
    ).reset_index(
        drop=True
    )

    print(
        f"\nFinal rows: "
        f"{len(final_df):,}"
    )

    print(
        "\nAttack-family distribution:"
    )

    distribution = (
        final_df["Attack_Family"]
        .value_counts()
    )

    print(
        distribution.to_string()
    )

    print(
        "\nPercentage distribution:"
    )

    percentages = (
        final_df["Attack_Family"]
        .value_counts(
            normalize=True
        )
        * 100
    )

    print(
        percentages.round(2).to_string()
    )

    # Save unified dataset.
    print(
        "\nSaving unified dataset..."
    )

    final_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # Create report.
    report = {

        "datasets": file_reports,

        "total_rows":
            int(len(final_df)),

        "class_distribution":
            {
                str(k): int(v)
                for k, v
                in distribution.items()
            },

        "class_percentages":
            {
                str(k): float(v)
                for k, v
                in percentages.items()
            },

        "classes": [
            "Benign",
            "Bot",
            "DoS",
            "Web Attack",
            "Infiltration",
        ],

        "benign_limit_per_file":
            MAX_BENIGN_PER_FILE
    }

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
        "\n========================================"
    )

    print(
        "       DATASET PREPARATION COMPLETE"
    )

    print(
        "========================================"
    )

    print(
        f"\nDataset saved to:"
        f"\n{OUTPUT_FILE}"
    )

    print(
        f"\nReport saved to:"
        f"\n{REPORT_FILE}"
    )


if __name__ == "__main__":
    main()