import pandas as pd
import numpy as np
import pickle

# ==== Config ====
PATH = "../DNP3/Model_Files"

scl_cols = ['frame.time_relative', 'frame.len', 'frame.cap_len', 'tcp.srcport',
       'tcp.dstport', 'tcp.len', 'tcp.window_size_value', 'tcp.time_delta',
       'dnp3.len', 'dnp3.ctrl', 'dnp3.dst_addr', 'dnp3.src_addr', 'dnp3.dir',
       'dnp3.func_code_link', 'dnp3.func_code', 'dnp3.payload_len']

training_features = ['frame.time_relative',
 'tcp.time_delta',
 'tcp.dstport',
 'tcp.srcport',
 'dnp3.src_addr',
 'dnp3.dst_addr',
 'dnp3.func_code',
 'frame.len',
 'tcp.window_size_value',
 'frame.cap_len'] 

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


# ==== Helpers ====
def preprocessed_data(df: pd.DataFrame):
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

    return df, df[scl_cols]


def load_pickle_files(PATH: str):
    """Load pre-trained KMeans model and scaler."""
    with open(f"{PATH}/DNP3_RF_best_model.pkl", "rb") as f:
        model = pickle.load(f)
    with open(f"{PATH}/dnp3_scaler_for_SL.pkl", "rb") as f:
        scaler = pickle.load(f)
    return model, scaler



def get_predictions(df_scaled: pd.DataFrame, model, scaler):
    """Predict labels and full probability distributions for each row."""
    CLASSES = ["RESTART_ATTACK", "CONTROL_ATTACK", "DNP3_RECON", "REPLAY_ATTACK", "DOS_ATTACK"]
    
    input_scaled = scaler.transform(df_scaled)
    df_scl = pd.DataFrame(input_scaled, columns=scl_cols)[training_features]

    # Predict probabilities
    y_proba = model.predict_proba(df_scl)

    # Predicted class indices
    y_pred_idx = y_proba.argmax(axis=1)

    # Map indices to labels
    predicted_labels = [CLASSES[i] for i in y_pred_idx]


    # Probability dataframe
    proba_df = pd.DataFrame(y_proba, columns=[f"prob_{cls}" for cls in CLASSES])

    # Print alert for each row
    for i, label in enumerate(predicted_labels):
        if label != "normal":
            # print(f"\033[91m⚠️  Attack detected in packet {i+1}: {label}\033[0m")
            confidence = y_proba[i].max()
            print(f"\033[91m🚨 Packet {i+1} | Attack: {label} | Confidence: {confidence:.2f}\033[0m")


    return predicted_labels, proba_df


# ==== Main ====
if __name__ == '__main__':
    df = pd.read_csv("dnp3_capture.csv")

    df_original, df_proc = preprocessed_data(df)

    model, scaler = load_pickle_files(PATH)
    labels, proba_df = get_predictions(df_proc, model, scaler)

    # Add results to original DataFrame
    df_original["predicted_label"] = labels
    df_original = df_original.reset_index(drop=True)
    proba_df = proba_df.reset_index(drop=True)

    df_original = pd.concat([df_original, proba_df], axis=1)
    print(df_original.head())
    df_original.to_excel("dnp3_capture_with_predictions_SL.xlsx", index=False)
    print("✅ Predictions with cluster scores saved to dnp3_capture_with_predictions_SL.csv")