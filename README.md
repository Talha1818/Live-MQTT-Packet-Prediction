# Live MQTT Packet Capture & Prediction

This repository demonstrates how to **capture live MQTT network traffic** from a local broker and predict potential attack types using a pre-trained machine learning model. It uses **Scapy** for packet capture and a **Random Forest classifier** for predictions.

---

## 🔗 Prerequisites

1. **Mosquitto MQTT Broker**  
   Install Mosquitto to run a local MQTT broker:  
   [https://mosquitto.org/download/](https://mosquitto.org/download/)

2. **MQTT Explorer** (optional, for monitoring)  
   A GUI tool to inspect MQTT messages:  
   [https://mqtt-explorer.com/](https://mqtt-explorer.com/)

3. **⚡ Setup & Run**  
    1. Start Local MQTT Broker  

    Start Mosquitto broker on default port 1883:
    ```bash
    mosquitto -v
    ```

    2. Run MQTT Explore
    Connect to localhost:1883 to visualize MQTT traffic.

    3. Capture Live MQTT Packets

        The capture_predict.py script captures live MQTT packets and generates predictions:

        ```bash

        python capture_predict.py


        Captures live packets for 30 seconds by default.

        Filters traffic on TCP port 1883 (MQTT).

        Extracts MQTT headers like CONNECT, PUBLISH, PINGREQ, etc.

        Saves captured packets to mqtt_capture.csv.
        ```

    4. Predict Using Pre-trained Model

        The same script also:
        
        ```bash

        Loads a pre-trained Random Forest model and scaler from ./Model_Files/.

        Processes packet features.

        Predicts attack labels (normal, malariaDoS, malformed, slowite, bruteforce, flood).

        Saves results with probabilities to mqtt_capture_with_predictions.csv.
        ```
4. **📝 Key Features**

    Extract MQTT-specific features:

    ```bash

    Control packet type (CONNECT, PUBLISH, etc.)

    QoS level

    Keepalive

    Payload size

    Extract TCP/IP metadata:

    Source/destination IP and port

    Packet length

    Flags and window size

    Generates predictions with probability distributions for each class.
    ```
5. **⚙️ Customization**

    ```bash

    Capture interface
    Update the network interface in capture_predict.py:

    iface = r"\Device\NPF_Loopback"  # Windows loopback


    Capture timeout
    Change timeout in the sniff() function:

    sniff(prn=packet_callback, filter="tcp port 1883", iface=iface, store=False, timeout=30)


    Classes and features
    Modify CLASSES and training_features in prediction.py if using a different model.
    ```

## Setup & Run
```bash
# 1. Clone the repository
Firstly, clone the repository using `git clone https://github.com/Talha1818/llm-self-pr-eval-swebench-inspect-ai.git`

# 2. Create a virtual environment
python -m venv env

# 3. Activate the virtual environment
# Windows:
.\env\Scripts\activate
# macOS/Linux:
source env/bin/activate

# 4. Install dependencies (if requirements.txt is available)
pip install -r requirements.txt

# 5. Run the main file
python capture_predict.py
```

## Live MQTT Packet Prediction
https://github.com/user-attachments/assets/ace9a6f8-acb2-4049-b7f2-bd8efcc37cf3


