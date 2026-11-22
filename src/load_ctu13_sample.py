from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PATH = PROJECT_ROOT / "CTU-13" / "capture20110817.binetflow.2format"
df = pd.read_csv(PATH, nrows=1_000, low_memory=False)
print(f"Rows sampled: {len(df):,}")
print("Columns:", list(df.columns))
print("Label counts:")
print(df["Label"].value_counts())
