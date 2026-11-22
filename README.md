# NetGuard: Graph-Based Botnet Detection

College capstone project exploring botnet detection with CTU-13 network-flow data, graph analysis, and later machine-learning evaluation.

## Current project status

- CTU-13 flow data is available locally in `CTU-13/`.
- A bounded sample loader and a data-quality profiler are available.
- The Streamlit dashboard provides exploratory graph and label views.
- No classifier has been trained yet. Dashboard status labels reflect the dataset's supplied labels, not project predictions.

## Project structure

```text
CTU-13/                 # Local CTU-13 flow file (not downloaded by the code)
data/                   # Future processed data; keep raw source data untouched
notebooks/              # Exploratory notebooks
results/                # Generated reports, figures, and future evaluation outputs
src/
  dashboard.py          # Streamlit visual dashboard
  load_ctu13_sample.py # Quick 1,000-row inspection
  profile_ctu13.py     # Data-quality profile generator
```

## Run from WSL

```bash
cd /mnt/c/Users/yayaj/OneDrive/Desktop/Botnet-Detection-Capstone
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## CTU-13 dataset setup

The CTU-13 dataset is not stored in this repository because the raw flow data is too large for normal GitHub tracking. Download the dataset from its official source or your course-provided copy, then place the required flow file at:

```text
CTU-13/capture20110817.binetflow.2format
```

The expected local layout is:

```text
Botnet-Detection-Capstone/
└── CTU-13/
    └── capture20110817.binetflow.2format
```

Do not rename the flow file unless you also update the `DATA_PATH` value in the scripts under `src/`. Raw datasets, the dataset archive, and virtual environments are intentionally excluded by `.gitignore`.

### Start the dashboard

```bash
python -m streamlit run src/dashboard.py
```

Open `http://localhost:8501` in a browser.

### Inspect a small data sample

```bash
python src/load_ctu13_sample.py
```

### Create a reproducible data profile

```bash
python src/profile_ctu13.py --rows 10000
```

This writes `results/ctu13_data_profile.json`. The script only profiles a sample; it does not modify raw CTU-13 data or train a model.

## Next milestones

1. Define a train/test split that prevents time or host leakage.
2. Build graph and flow feature engineering in a separate, reproducible module.
3. Train baseline models and evaluate precision, recall, F1, ROC-AUC, and false-positive rate.
4. Connect evaluated results to the dashboard.
