import pandas as pd
import numpy as np
import pickle

# ==== Config ====
PATH = "../DNP3/Model_Files"



# Map cluster index -> attack label (build this from training via
# pd.crosstab(clusters, df["label"]).idxmax() and fill in below)
CLUSTER_LABEL_MAP = {
    0: "RESTART_ATTACK",
    1: "CONTROL_ATTACK",
    2: "DNP3_RECON",
    3: "REPLAY_ATTACK",
    4: "DOS_ATTACK",
}

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

global training_features

# ==== Helpers ====
def preprocessed_data(df: pd.DataFrame, ALL_FEATURES=False):

    ##################################### ALL FEATURES (no selection) #####################################

    if ALL_FEATURES:
        scl_cols = ['frame.time_relative', 'frame.len', 'frame.cap_len', 'tcp.srcport',
        'tcp.dstport', 'tcp.len', 'tcp.window_size_value', 'tcp.time_delta',
        'dnp3.len', 'dnp3.ctrl', 'dnp3.dst_addr', 'dnp3.src_addr', 'dnp3.dir',
        'dnp3.func_code_link', 'dnp3.func_code', 'dnp3.payload_len']
    else:

        scl_cols = ['tcp.time_delta', 'frame.time_relative', 'tcp.window_size_value',
       'dnp3.dst_addr', 'dnp3.src_addr', 'dnp3.len', 'frame.len',
       'dnp3.func_code', 'dnp3.ctrl', 'tcp.len']

    training_features = scl_cols  # update this if your KMeans was trained on a subset


    """Filter + clean dataframe, add encoded DNP3 labels."""
    df = df[df["dnp3.func_code"].notna()].copy()
    print(f"✅ Filtered to {len(df)} packets with valid DNP3 function codes")

    df['dnp3.fcb'] = df['dnp3.fcb'].fillna(-1)
    df['dnp3.fcv'] = df['dnp3.fcv'].fillna(-1)
    df['dnp3.payload_len'] = df['dnp3.payload_len'].fillna(0)
    df['frame.time_delta'] = df.get('frame.time_delta', 0)
    df['tcp.time_delta'] = df['tcp.time_delta'].fillna(0)

    mapping_dnp3 = {v: k for k, v in DNP3_FUNC_NAMES.items()}
    df["dnp3_func_name_label"] = df["dnp3.func_name"].map(mapping_dnp3)

    return df, df[scl_cols], training_features, scl_cols


def load_pickle_files(PATH: str, all_features: bool = False):
    """Load pre-trained model and scaler based on feature set."""
    
    if all_features:
        model_file  = "kmeans_model_dnp3_all_features.pkl"
        scaler_file = "dnp3_scaler_final_all_features.pkl"
    else:
        model_file  = "kmeans_model_dnp3.pkl"
        scaler_file = "dnp3_scaler_final.pkl"
    
    with open(f"{PATH}/{model_file}", "rb") as f:
        model = pickle.load(f)
    with open(f"{PATH}/{scaler_file}", "rb") as f:
        scaler = pickle.load(f)
        
    return model, scaler


def get_predictions(df_scaled: pd.DataFrame, model, scaler, training_features, scl_cols):
    """Predict cluster labels and distance-based confidence scores for each row."""

    input_scaled = scaler.transform(df_scaled)
    df_scl = pd.DataFrame(input_scaled, columns=scl_cols)[training_features]

    # Predict cluster assignments
    cluster_idx = model.predict(df_scl)

    # Distance to each cluster center
    distances = model.transform(df_scl)

    # Convert distances to similarity-style scores (closer = higher score)
    inv_distances = 1 / (distances + 1e-9)
    scores = inv_distances / inv_distances.sum(axis=1, keepdims=True)

    # Map cluster index to attack label
    predicted_labels = [CLUSTER_LABEL_MAP.get(c, f"cluster_{c}") for c in cluster_idx]

    # Score dataframe
    proba_df = pd.DataFrame(
        scores,
        columns=[f"score_{CLUSTER_LABEL_MAP.get(i, f'cluster_{i}')}" for i in range(scores.shape[1])]
    )

    # Print alert for each row
    for i, label in enumerate(predicted_labels):
        if label != "RESTART_ATTACK":  # adjust if you have a "normal" cluster
            confidence = scores[i].max()
            print(f"\033[91m🚨 Packet {i+1} | Cluster: {cluster_idx[i]} | Label: {label} | Confidence: {confidence:.2f}\033[0m")

    return predicted_labels, proba_df


# ==== Main ====
if __name__ == '__main__':
    df = pd.read_csv("dnp3_capture.csv")

    all_features = True
    df_original, df_proc, training_features, scl_cols = preprocessed_data(df, ALL_FEATURES=all_features)

    model, scaler = load_pickle_files(PATH, all_features=all_features)
    labels, proba_df = get_predictions(df_proc, model, scaler, training_features, scl_cols)

    # Add results to original DataFrame
    df_original["predicted_label"] = labels
    df_original = df_original.reset_index(drop=True)
    proba_df = proba_df.reset_index(drop=True)

    df_original = pd.concat([df_original, proba_df], axis=1)
    print(df_original.head())
    df_original.to_csv("dnp3_capture_with_predictions.csv", index=False)
    print("✅ Predictions with cluster scores saved to dnp3_capture_with_predictions.csv")