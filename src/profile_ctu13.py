"""Create a small reproducible data-quality profile of the CTU-13 flow file.

This is exploratory preparation only. It does not train or evaluate a model.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = PROJECT_ROOT / "CTU-13" / "capture20110817.binetflow.2format"
REPORT_PATH = PROJECT_ROOT / "results" / "ctu13_data_profile.json"
REQUIRED_COLUMNS = {"SrcAddr", "DstAddr", "Proto", "Label"}


def label_status(label: object) -> str:
    """Group CTU-13 labels for an exploratory overview, not model targets."""
    text = str(label).lower()
    if "botnet" in text or "malicious" in text:
        return "malicious"
    if "background" in text or text in {"nan", "normal"}:
        return "normal/background"
    return "other"


def profile_flows(rows: int) -> dict[str, object]:
    flows = pd.read_csv(DATA_PATH, nrows=rows, low_memory=False)
    missing = sorted(REQUIRED_COLUMNS.difference(flows.columns))
    if missing:
        raise ValueError(f"Dataset is missing required columns: {', '.join(missing)}")

    statuses = flows["Label"].map(label_status)
    return {
        "source_file": str(DATA_PATH),
        "rows_sampled": len(flows),
        "columns": list(flows.columns),
        "missing_values": {column: int(count) for column, count in flows.isna().sum().items() if count},
        "unique_source_ips": int(flows["SrcAddr"].nunique()),
        "unique_destination_ips": int(flows["DstAddr"].nunique()),
        "protocol_counts": {str(key): int(value) for key, value in flows["Proto"].value_counts().items()},
        "label_counts": {str(key): int(value) for key, value in flows["Label"].value_counts().items()},
        "overview_status_counts": {str(key): int(value) for key, value in statuses.value_counts().items()},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile a bounded CTU-13 flow sample.")
    parser.add_argument("--rows", type=int, default=10_000, help="Number of flow rows to inspect.")
    arguments = parser.parse_args()

    if not DATA_PATH.exists():
        raise FileNotFoundError(f"CTU-13 flow file not found: {DATA_PATH}")
    if arguments.rows <= 0:
        raise ValueError("--rows must be a positive integer")

    report = profile_flows(arguments.rows)
    REPORT_PATH.parent.mkdir(exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print(f"\nSaved profile: {REPORT_PATH}")


if __name__ == "__main__":
    main()
