import os
import socket
import pandas as pd
from tqdm import tqdm
from scapy.all import sniff, rdpcap, TCP, IP, Ether, Raw
from prediction import preprocessed_data, load_pickle_files, get_predictions

# === MQTT control packet names ===
MQTT_CTRL_NAMES = {
    1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
    5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
    9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK",
    12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT", 15: "AUTH"
}

def decode_mqtt_remaining_length(payload, offset=1):
    """Decode MQTT Remaining Length field."""
    multiplier, value, bytes_used = 1, 0, 0
    while True:
        if offset + bytes_used >= len(payload):
            return None, bytes_used
        encoded_byte = payload[offset + bytes_used]
        value += (encoded_byte & 0x7F) * multiplier
        bytes_used += 1
        if (encoded_byte & 0x80) == 0:
            break
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            return None, bytes_used
    return value, bytes_used

# === Storage ===
mqtt_rows = []
pkt_counter = 0
first_time, last_time = None, None

def packet_callback(pkt):
    global pkt_counter, first_time, last_time, mqtt_rows

    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    tcp_layer = pkt[TCP]
    ip_layer = pkt[IP]
    eth_layer = pkt[Ether] if pkt.haslayer(Ether) else None

    # Only MQTT traffic
    if tcp_layer.sport != 1883 and tcp_layer.dport != 1883:
        return

    pkt_counter += 1
    if first_time is None:
        first_time = float(pkt.time)
    frame_time = float(pkt.time)
    frame_time_relative = frame_time - first_time
    frame_time_delta = None if last_time is None else frame_time - last_time
    last_time = frame_time

    row = {
        # === File / Frame ===
        "frame.number": pkt_counter,
        "frame.time_epoch": frame_time,
        "frame.time_relative": frame_time_relative,
        "frame.time_delta": frame_time_delta,
        "frame.len": len(pkt),
        "frame.cap_len": len(bytes(pkt)),

        # === Ethernet ===
        "eth.src": eth_layer.src if eth_layer else None,
        "eth.dst": eth_layer.dst if eth_layer else None,

        # === IP ===
        "ip.src": ip_layer.src,
        "ip.dst": ip_layer.dst,
        "ip.proto": ip_layer.proto,

        # === TCP ===
        "tcp.srcport": tcp_layer.sport,
        "tcp.dstport": tcp_layer.dport,
        "tcp.flags": tcp_layer.flags.value,
        "tcp.len": len(tcp_layer.payload),
        "tcp.window_size_value": tcp_layer.window,
        "tcp.checksum": tcp_layer.chksum,
        "tcp.stream": None,  # flow tracking not implemented
        "tcp.analysis.initial_rtt": None,  # RTT calc not implemented
        "tcp.time_delta": frame_time_delta,

        # === MQTT (default init) ===
        "mqtt_present": False,
        "mqtt_ctrl_type": None,
        "mqtt_ctrl_name": None,
        "mqtt_flags": None,
        "mqtt_remaining_len": None,
        "mqtt_qos": None,
        "mqtt_keepalive": None,
        "mqtt_payload_size": None,
    }

    # === MQTT parsing ===
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw])
        if len(payload) > 0:
            row["mqtt_present"] = True
            row["mqtt_ctrl_type"] = payload[0] >> 4
            row["mqtt_flags"] = payload[0] & 0x0F
            row["mqtt_ctrl_name"] = MQTT_CTRL_NAMES.get(row["mqtt_ctrl_type"], "UNKNOWN")

            remaining_len, used_bytes = decode_mqtt_remaining_length(payload)
            row["mqtt_remaining_len"] = remaining_len
            row["mqtt_payload_size"] = remaining_len

            # QoS (for PUBLISH)
            if row["mqtt_ctrl_type"] == 3:  # PUBLISH
                qos = (row["mqtt_flags"] & 0x06) >> 1
                row["mqtt_qos"] = qos

            # Keepalive (for CONNECT)
            if row["mqtt_ctrl_type"] == 1 and remaining_len:
                try:
                    variable_header = payload[1 + used_bytes:]
                    keepalive = int.from_bytes(variable_header[-2:], byteorder="big")
                    row["mqtt_keepalive"] = keepalive
                except Exception:
                    pass

    mqtt_rows.append(row)


if __name__ == "__main__":

    # Replace with your Npcap loopback device name
    iface = r"\Device\NPF_Loopback"
    PATH = "./Model_Files"

    # Capture for 30 seconds
    print("🚦 Capturing live MQTT packets on port 1883...")
    sniff(prn=packet_callback, filter="tcp port 1883", iface=iface, store=False, timeout=30)

    print(f"\n✅ Done, captured {len(mqtt_rows)} MQTT packets")

    # Save to DataFrame
    df = pd.DataFrame(mqtt_rows)
    df = df[df["mqtt_ctrl_type"].notna()].copy()
    # print(f"✅ Filtered to {len(df)} packets with valid MQTT control headers")

    df.to_csv("mqtt_capture.csv", index=False)
    print("📂 Saved to mqtt_capture.csv")
    # print(df.head())

    df_original, df_proc = preprocessed_data(df)

    model, scaler = load_pickle_files(PATH)
    labels, proba_df = get_predictions(df_proc, model, scaler)

    # Add results to original DataFrame
    df_original["predicted_label"] = labels
    # Reset index to avoid misalignment
    df_original = df_original.reset_index(drop=True)
    proba_df = proba_df.reset_index(drop=True)

    df_original = pd.concat([df_original, proba_df], axis=1)
    # print(df_original.head())
    df_original.to_csv("mqtt_capture_with_predictions.csv", index=False)
    print("✅ Predictions with full probabilities saved to mqtt_capture_with_predictions.csv")

