import pandas as pd
import numpy as np
import pickle
from collections import deque
from tqdm import tqdm

# ==== Config ====
PATH = "../DNP3/Model_Files"

# ── Binary ──────────────────────────────────────────────────────────────────
BINARY_CLASSES = ["NORMAL", "ATTACK"]

BINARY_TRAINING_FEATURES = [
    'time_delta_max', 'time_delta_range', 'time_delta_min',
    'window_size_std', 'window_size_mean', 'time_delta_mean',
    'time_delta_std', 'time_delta_cv', 'frame_len_mean',
    'window_size_min', 'frame_len_min', 'read_ratio',
    'frame_len_std', 'response_ratio', 'dnp3_dir_ratio',
    'frame_len_range', 'dnp3_ctrl_mode', 'confirm_ratio',
    'frame_len_max'
]

# ── Multiclass ───────────────────────────────────────────────────────────────
MULTICLASS_CLASSES = {
    0: "NORMAL",
    1: "RESTART_ATTACK",
    2: "CONTROL_ATTACK",
    3: "RARE_ATTACK"
}

MULTICLASS_TRAINING_FEATURES = [
    'time_delta_mean', 'time_delta_max', 'time_delta_std',
    'time_delta_range', 'time_delta_min', 'time_delta_cv',
    'window_size_std', 'window_size_min', 'window_size_mean',
    'frame_len_mean', 'frame_len_std', 'frame_len_max',
    'response_ratio', 'read_ratio', 'dnp3_dir_ratio',
    'frame_len_range'
    # Note: frame_len_min, dnp3_ctrl_mode, confirm_ratio dropped in multiclass
    # (low SHAP importance — below 0.003 threshold)
]

# ── Shared ───────────────────────────────────────────────────────────────────
continuous_features = [
    "time_delta_mean", "time_delta_std", "time_delta_min",
    "time_delta_max", "time_delta_range", "time_delta_cv",
    "frame_len_mean", "frame_len_std", "frame_len_max", "frame_len_range",
    "window_size_mean", "window_size_std", "window_size_min"
]

DNP3_FUNC_NAMES = {
    0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT",
    4: "OPERATE", 5: "DIRECT_OPERATE", 6: "DIRECT_OPERATE_NR",
    7: "IMMED_FREEZE", 8: "IMMED_FREEZE_NR", 9: "FREEZE_CLEAR",
    10: "FREEZE_CLEAR_NR", 11: "FREEZE_AT_TIME", 12: "FREEZE_AT_TIME_NR",
    13: "COLD_RESTART", 14: "WARM_RESTART", 15: "INITIALIZE_DATA",
    16: "INITIALIZE_APPL", 17: "START_APPL", 18: "STOP_APPL",
    19: "SAVE_CONFIG", 20: "ENABLE_UNSOLICITED", 21: "DISABLE_UNSOLICITED",
    22: "ASSIGN_CLASS", 23: "DELAY_MEASURE", 24: "RECORD_CURRENT_TIME",
    129: "RESPONSE", 130: "UNSOLICITED_RESPONSE",
}

# Shared func_names only — leakage-free (attack-specific ones excluded)
SHARED_FUNCS = {"READ", "RESPONSE", "CONFIRM"}


# ==== Helpers ====

def preprocessed_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean + preprocess raw captured DataFrame.
    - Filters to shared func_names only (no leakage)
    - Creates binary func features (is_response, is_read, is_confirm)
    - Clips negative timing values caused by float precision
    Works for both binary and multiclass pipelines.
    """
    df = df[df["dnp3.func_code"].notna()].copy()
    print(f"✅ Filtered to {len(df)} packets with valid DNP3 function codes")

    # Fill missing timing values
    df["frame.time_delta"] = df["frame.time_delta"].fillna(0)
    df["tcp.time_delta"]   = df["tcp.time_delta"].fillna(0)

    # Add func_name if not present
    if "dnp3.func_name" not in df.columns:
        df["dnp3.func_name"] = df["dnp3.func_code"].map(DNP3_FUNC_NAMES).fillna("UNKNOWN")

    # Keep only shared func_names — attack-exclusive ones cause leakage
    df = df[df["dnp3.func_name"].isin(SHARED_FUNCS)].copy()
    print(f"✅ After shared func filter: {len(df)} packets")

    # Binary func features
    df["is_response"] = (df["dnp3.func_name"] == "RESPONSE").astype(int)
    df["is_read"]     = (df["dnp3.func_name"] == "READ").astype(int)
    df["is_confirm"]  = (df["dnp3.func_name"] == "CONFIRM").astype(int)

    # Clip negative near-zero timing values (float precision artifact)
    df["frame.time_delta"] = df["frame.time_delta"].clip(lower=0)
    df["tcp.time_delta"]   = df["tcp.time_delta"].clip(lower=0)

    # Sort by time
    df = df.sort_values("frame.time_relative").reset_index(drop=True)

    return df


def extract_window_features(window_df: pd.DataFrame, mode: str = "binary") -> pd.DataFrame:
    """
    Extract aggregated features from a window of 10 raw packets.
    Returns a single-row DataFrame with engineered features.

    Parameters
    ----------
    window_df : DataFrame of exactly `window_size` raw packets
    mode      : "binary" or "multiclass"
                - binary     → includes dnp3_ctrl_mode + confirm_ratio + frame_len_min (19 features)
                - multiclass → excludes those 3 low-importance features (16 features)
    """
    td = window_df["frame.time_delta"]
    fl = window_df["frame.len"]
    ws = window_df["tcp.window_size_value"]

    features = {
        # Timing features
        "time_delta_mean"  : td.mean(),
        "time_delta_std"   : td.std(),
        "time_delta_min"   : td.min(),
        "time_delta_max"   : td.max(),
        "time_delta_range" : td.max() - td.min(),
        "time_delta_cv"    : td.std() / (td.mean() + 1e-9),

        # Packet size features
        "frame_len_mean"   : fl.mean(),
        "frame_len_std"    : fl.std(),
        "frame_len_min"    : fl.min(),   # binary only
        "frame_len_max"    : fl.max(),
        "frame_len_range"  : fl.max() - fl.min(),

        # TCP window features
        "window_size_mean" : ws.mean(),
        "window_size_std"  : ws.std(),
        "window_size_min"  : ws.min(),

        # Protocol behavior ratios
        "response_ratio"   : window_df["is_response"].mean(),
        "read_ratio"       : window_df["is_read"].mean(),
        "confirm_ratio"    : window_df["is_confirm"].mean(),   # binary only

        # DNP3 control — categorical (68/196) → binary
        "dnp3_ctrl_mode"   : int(window_df["dnp3.ctrl"].mode()[0] == 196),  # binary only
        "dnp3_dir_ratio"   : window_df["dnp3.dir"].mean(),
    }

    # Drop multiclass-irrelevant features (low SHAP importance < 0.003)
    if mode == "multiclass":
        for drop_col in ["frame_len_min", "confirm_ratio", "dnp3_ctrl_mode"]:
            features.pop(drop_col, None)

    return pd.DataFrame([features])


def load_pickle_files(
    path: str,
    model_filename: str,
    scaler_filename: str
):
    """
    Load pre-trained classifier and scaler from pickle files.

    Parameters
    ----------
    path             : directory containing the pickle files
    model_filename   : filename of the model pkl  (e.g. "DNP3_RF_best_model.pkl"
                       or "dnp3_multiclass_rf.pkl")
    scaler_filename  : filename of the scaler pkl (e.g. "dnp3_scaler_for_SL.pkl"
                       or "dnp3_multiclass_scaler.pkl")
    """
    with open(f"{path}/{model_filename}", "rb") as f:
        model = pickle.load(f)
    with open(f"{path}/{scaler_filename}", "rb") as f:
        scaler = pickle.load(f)
    print(f"✅ Model  loaded  : {model_filename}")
    print(f"✅ Scaler loaded  : {scaler_filename}")
    return model, scaler


def get_predictions(
    df: pd.DataFrame,
    model,
    scaler,
    mode: str = "binary",
    window_size: int = 10
):
    """
    Sliding window prediction — every packet gets a prediction after
    the first (window_size - 1) packets are buffered.

    Parameters
    ----------
    df          : preprocessed DataFrame (output of preprocessed_data)
    model       : trained classifier (binary or multiclass RF)
    scaler      : fitted StandardScaler
    mode        : "binary" or "multiclass"
    window_size : number of packets per window (default 10)

    Returns
    -------
    predictions : list of predicted label strings (None for first window_size-1 packets)
    proba_df    : DataFrame with per-class probabilities
    """
    # Select correct config based on mode
    if mode == "binary":
        classes_list   = BINARY_CLASSES
        training_feats = BINARY_TRAINING_FEATURES
    elif mode == "multiclass":
        classes_list   = list(MULTICLASS_CLASSES.values())   # ["NORMAL","RESTART_ATTACK","CONTROL_ATTACK","RARE_ATTACK"]
        training_feats = MULTICLASS_TRAINING_FEATURES
    else:
        raise ValueError(f"mode must be 'binary' or 'multiclass', got: '{mode}'")

    df = df.reset_index(drop=True)
    predictions = [None] * len(df)
    all_probas  = [None] * len(df)

    for i in tqdm(range(window_size - 1, len(df)), desc=f"Predicting [{mode}]", unit="packet"):
        window_df = df.iloc[i - window_size + 1 : i + 1]

        # Feature engineering (mode-aware)
        X = extract_window_features(window_df, mode=mode)

        # Scale continuous features
        X[continuous_features] = scaler.transform(X[continuous_features])

        # Reorder to match exact training feature order
        X = X[training_feats]

        # Predict
        y_proba    = model.predict_proba(X)[0].astype(float)
        y_pred_idx = y_proba.argmax()
        label      = classes_list[y_pred_idx]
        confidence = float(y_proba[y_pred_idx])

        predictions[i] = label
        all_probas[i]  = {f"prob_{cls}": round(float(p), 4) for cls, p in zip(classes_list, y_proba)}

        # Alert on attack
        if label != "NORMAL":
            print(f"\033[91m🚨 Packet {i+1} | {label} detected | Confidence: {confidence:.2f}\033[0m")

    # Build proba DataFrame
    proba_df = pd.DataFrame([
        p if p is not None else {f"prob_{cls}": None for cls in classes_list}
        for p in all_probas
    ])

    return predictions, proba_df


# ==== Main ====
if __name__ == '__main__':

    # ── Choose mode here ─────────────────────────────────────────────────────
    MODE = "multiclass"       # "binary" or "multiclass"
    # ─────────────────────────────────────────────────────────────────────────

    # Pickle filenames differ per mode — update as needed
    if MODE == "binary":
        MODEL_FILE  = "DNP3_RF_best_model (1).pkl"
        SCALER_FILE = "dnp3_scaler_for_SL (1).pkl"
        OUTPUT_FILE = "dnp3_capture_with_predictions_SL_binary.xlsx"
    else:
        MODEL_FILE  = "DNP3_RF_best_model__RFFF.pkl"
        SCALER_FILE = "dnp3_scaler_for_SL_RF.pkl"
        OUTPUT_FILE = "dnp3_capture_with_predictions_SL_multiclass.xlsx"

    # Load raw capture
    df_raw = pd.read_csv("dnp3_capture.csv")

    # Preprocess (same for both modes)
    df_proc = preprocessed_data(df_raw)

    # Load model + scaler
    model, scaler = load_pickle_files(
        path=PATH,
        model_filename=MODEL_FILE,
        scaler_filename=SCALER_FILE
    )

    # Predict
    labels, proba_df = get_predictions(
        df=df_proc,
        model=model,
        scaler=scaler,
        mode=MODE,
        window_size=10
    )

    # Save output
    df_proc = df_proc.reset_index(drop=True)
    proba_df = proba_df.reset_index(drop=True)
    df_proc["predicted_label"] = labels

    df_out = pd.concat([df_proc, proba_df], axis=1)
    df_out.to_excel(OUTPUT_FILE, index=False)
    print(f"✅ Predictions saved to {OUTPUT_FILE}")