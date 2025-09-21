import pandas as pd
import pickle

# ==== Config ====
PATH = "./Model_Files"

scl_cols = [
    'frame.time_relative', 'frame.len', 'frame.cap_len', 'tcp.srcport',
    'tcp.dstport', 'tcp.flags', 'tcp.len', 'tcp.window_size_value',
    'tcp.time_delta', 'mqtt_ctrl_type', 'mqtt_flags', 'mqtt_remaining_len',
    'mqtt_qos', 'mqtt_keepalive', 'mqtt_payload_size',
    'mqtt_ctrl_name_label'
]

training_features = [
    'frame.time_relative', 'frame.len', 'frame.cap_len',
    'tcp.dstport', 'tcp.flags', 'tcp.len',
    'tcp.window_size_value', 'mqtt_flags',
    'mqtt_qos', 'mqtt_keepalive', 'mqtt_ctrl_name_label'
]

CLASSES = ['normal', 'malariaDoS', 'malformed', 'slowite', 'bruteforce', 'flood']

# ==== Helpers ====
def preprocessed_data(df: pd.DataFrame):
    """Filter + clean dataframe, add encoded MQTT labels."""
    df = df[df["mqtt_ctrl_type"].notna()].copy()
    print(f"✅ Filtered to {len(df)} packets with valid MQTT control headers")

    df['mqtt_qos'] = df['mqtt_qos'].fillna(-1)
    # df['mqtt_keepalive'] = df['mqtt_keepalive'].fillna(0)
    df['mqtt_keepalive'] = pd.to_numeric(df['mqtt_keepalive'], errors='coerce').fillna(0).astype(int)


    mapping_mqtt = {
        "PUBLISH": 0, "PUBACK": 1, "PUBREL": 2, "CONNACK": 3, "CONNECT": 4,
        "UNKNOWN": 5, "PUBCOMP": 6, "SUBSCRIBE": 7, "SUBACK": 8, "PUBREC": 9,
        "DISCONNECT": 10, "PINGRESP": 11, "PINGREQ": 12, "UNSUBSCRIBE": 13,
        "UNSUBACK": 14, "AUTH": 15,
    }

    df["mqtt_ctrl_name_label"] = df["mqtt_ctrl_name"].map(mapping_mqtt)

    return df, df[scl_cols]


def load_pickle_files(PATH: str):
    """Load pre-trained model and scaler."""
    with open(f"{PATH}/RF_best_model.pkl", "rb") as f:
        model = pickle.load(f)
    with open(f"{PATH}/scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    return model, scaler


def get_predictions(df_scaled: pd.DataFrame, model, scaler):
    """Predict labels and full probability distributions for each row."""
    input_scaled = scaler.transform(df_scaled)
    df_scl = pd.DataFrame(input_scaled, columns=scl_cols)[training_features]

    # Predict probabilities for all rows
    y_proba = model.predict_proba(df_scl)

    # Get predicted indices
    y_pred_idx = y_proba.argmax(axis=1)

    # Map to labels
    predicted_labels = [CLASSES[i] for i in y_pred_idx]

    # Put all probabilities into a DataFrame
    proba_df = pd.DataFrame(y_proba, columns=[f"prob_{cls}" for cls in CLASSES])

    return predicted_labels, proba_df


# ==== Main ====
if __name__ == '__main__':
    df = pd.read_csv("mqtt_capture.csv")

    df_original, df_proc = preprocessed_data(df)

    model, scaler = load_pickle_files(PATH)
    labels, proba_df = get_predictions(df_proc, model, scaler)

    # Add results to original DataFrame
    df_original["predicted_label"] = labels
    # Reset index to avoid misalignment
    df_original = df_original.reset_index(drop=True)
    proba_df = proba_df.reset_index(drop=True)

    df_original = pd.concat([df_original, proba_df], axis=1)
    print(df_original.head())
    df_original.to_csv("mqtt_capture_with_predictions.csv", index=False)
    print("✅ Predictions with full probabilities saved to mqtt_capture_with_predictions.csv")
