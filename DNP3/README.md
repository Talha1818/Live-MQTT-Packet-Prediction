# Live DNP3 Packet Capture & Prediction

This repository demonstrates how to **capture live DNP3 network traffic** between a master and an outstation, and predict potential attack types using a pre-trained machine learning model. It uses **Scapy** for packet capture and a **clustering-based model** for predictions.

---

## 🔗 Prerequisites

1. **FreyrSCADA DNP3 Library**
   Used to simulate a DNP3 Master and Outstation locally:
   [https://www.freyrscada.com/](https://www.freyrscada.com/)

    1.1 **Downloading and Installing Npcap (Packet capture library for Windows)**
        Install Npcap for packet capture on Windows:
        [https://npcap.com/#download/](https://npcap.com/#download)

2. **DNP3 Outstation & Master Scripts**
   This repo includes `dnp3_outstation.py` (server) and `dnp3_master.py` (client), both configured to communicate over TCP port `20003`.

3. **⚡ Setup & Run**

    1. Start the DNP3 Outstation (Server)

    ```bash
    python dnp3_outstation.py
    ```

    This starts a DNP3 outstation listening on `127.0.0.1:20003` with binary/analog input and output points configured.

    2. Start the DNP3 Master (Client)

    ```bash
    python dnp3_master.py
    ```

    This connects to the outstation on port `20003` and begins polling/exchanging DNP3 traffic.

    3. Capture Live DNP3 Packets

    The `capture_predict_dnp3.py` script captures live DNP3 packets and generates predictions:

    ```bash
    python capture_predict_dnp3.py
    ```

    ```bash
    Captures live packets for 30 seconds by default.

    Filters traffic on TCP ports 20000-20003 (DNP3).

    Extracts DNP3 data link and application layer headers (function code, control byte, addresses, etc.).

    Saves captured packets to dnp3_capture.csv.
    ```

    4. Predict Using Pre-trained Model

    The same script also:

    ```bash
    Loads a pre-trained clustering model and scaler from ./Model_Files/.

    Processes packet features.

    Predicts attack labels (RESTART_ATTACK, CONTROL_ATTACK, DNP3_RECON, REPLAY_ATTACK, DOS_ATTACK).

    Saves results with cluster confidence scores to dnp3_capture_with_predictions.xlsx, with attack rows highlighted in red.
    ```

4. **📝 Key Features**

    Extract DNP3-specific features:

    ```bash

    Data link control byte breakdown (DIR, PRM, FCB, FCV, function code)

    Application layer function code and function name

    Source/destination DNP3 addresses

    Payload length

    Extract TCP/IP metadata:

    Source/destination IP and port

    Packet length

    Flags and window size

    Generates predictions with cluster confidence scores for each class.
    ```
5. **⚙️ Customization**

    ```bash

    Capture interface
    Update the network interface in capture_predict_dnp3.py:

    iface = r"\Device\NPF_Loopback"  # Windows loopback


    Capture timeout / port range
    Change timeout or filter in the sniff() function:

    sniff(prn=packet_callback, filter="tcp portrange 20000-20003", iface=iface, store=False, timeout=30)


    Classes and features
    Modify CLUSTER_LABEL_MAP and training_features in prediction.py if using a different model.
    ```

## Setup & Run
```bash
# 1. Clone the repository
Firstly, clone the repository using `git clone https://github.com/Talha1818/Live-DNP3-Packet-Prediction.git`

# 2. Create a virtual environment
python -m venv env

# 3. Activate the virtual environment
# Windows:
.\env\Scripts\activate
# macOS/Linux:
source env/bin/activate

# 4. Install dependencies (if requirements.txt is available)
pip install -r requirements.txt

# 5. Start the Outstation (Server)
python dnp3_outstation.py

# 6. Start the Master (Client) in a separate terminal
python dnp3_master.py

# 7. Run the capture & prediction script
python capture_predict_dnp3.py
```

## Live DNP3 Packet Prediction


https://github.com/user-attachments/assets/271cf865-65f1-4c13-ae08-d3464ab8b787



