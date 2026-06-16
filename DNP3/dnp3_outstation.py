# dnp3_outstation.py — exact FreyrSCADA example, port changed to 20003
import ctypes
import time
import struct
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

def cbColdRestart(u16ObjectId, ptWriteID, ptErrorValue):
    print("⚠️  COLD RESTART received!")
    return 0

def cbWarmRestart(u16ObjectId, ptWriteID, ptErrorValue):
    print("⚠️  WARM RESTART received!")
    return 0

def cbWrite(u16ObjectId, eFunctionID, ptWriteID, ptWriteValue, ptWriteParams, ptErrorValue):
    print("📝 WRITE received!")
    return 0

def cbSelect(u16ObjectId, psSelectID, psSelectValue, psSelectParams, ptErrorValue):
    print("🔘 SELECT received!")
    return 0

def cbOperate(u16ObjectId, psOperateID, psOperateValue, psOperateParams, ptErrorValue):
    print("⚡ OPERATE received!")
    return 0

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

def main():
    print("**** DNP3 Outstation Server ****")

    if dnp3_lib.DNP3GetLibraryVersion().decode("utf-8") != DNP3_VERSION:
        print("❌ Version Mismatch!")
        exit(0)

    print(f"Library Version : {dnp3_lib.DNP3GetLibraryVersion().decode('utf-8')}")

    i16ErrorCode = ctypes.c_short()
    tErrorValue  = ctypes.c_short()

    # ── Parameters ──
    sParameters = sDNP3Parameters()
    sParameters.eAppFlag                   = eApplicationFlag.APP_SERVER
    sParameters.ptReadCallback             = ctypes.cast(None, DNP3ReadCallback)
    sParameters.ptWriteCallback            = DNP3WriteCallback(cbWrite)
    sParameters.ptUpdateCallback           = ctypes.cast(None, DNP3UpdateCallback)
    sParameters.ptSelectCallback           = DNP3ControlSelectCallback(cbSelect)
    sParameters.ptOperateCallback          = DNP3ControlOperateCallback(cbOperate)
    sParameters.ptDebugCallback            = DNP3DebugMessageCallback(cbDebug)
    sParameters.ptUpdateIINCallback        = ctypes.cast(None, DNP3UpdateIINCallback)
    sParameters.ptClientPollStatusCallback = ctypes.cast(None, DNP3ClientPollStatusCallback)
    sParameters.ptClientStatusCallback     = ctypes.cast(None, DNP3ClientStatusCallback)
    sParameters.ptColdRestartCallback      = DNP3ColdRestartCallback(cbColdRestart)
    sParameters.ptWarmRestartCallback      = DNP3WarmRestartCallback(cbWarmRestart)
    sParameters.ptDeviceAttrCallback       = ctypes.cast(None, DNP3DeviceAttributeCallback)
    sParameters.u32Options                 = 0
    sParameters.u16ObjectId               = 1

    myServer = dnp3_lib.DNP3Create(ctypes.byref(sParameters), ctypes.byref(i16ErrorCode), ctypes.byref(tErrorValue))
    if i16ErrorCode.value != 0:
        print(f"❌ DNP3Create() failed: {errorcodestring(i16ErrorCode)}")
        exit(0)
    print("✅ Server object created")

    while True:
        sDNP3Config = sDNP3ConfigurationParameters()

        # ── TCP port 20003 ──
        sDNP3Config.sDNP3ServerSet.sServerCommunicationSet.eCommMode = eCommunicationMode.TCP_IP_MODE
        sDNP3Config.sDNP3ServerSet.sServerCommunicationSet.sEthernetCommsSet.sEthernetportSet.ai8FromIPAddress = "127.0.0.1".encode('utf-8')
        sDNP3Config.sDNP3ServerSet.sServerCommunicationSet.sEthernetCommsSet.sEthernetportSet.u16PortNumber    = 20003  # ← changed

        # ── Protocol ──
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u16SlaveAddress            = 1
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u16MasterAddress           = 2
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u32LinkLayerTimeout        = 10000
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u32ApplicationLayerTimeout = 20000
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u32TimeSyncIntervalSeconds = 90

        # ── Static Variations ──
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sStaticVariation.eDeStVarBI  = eDefaultStaticVariationBinaryInput.BI_WITH_FLAGS
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sStaticVariation.eDeStVarDBI = eDefaultStaticVariationDoubleBitBinaryInput.DBBI_WITH_FLAGS
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sStaticVariation.eDeStVarBO  = eDefaultStaticVariationBinaryOutput.BO_WITH_FLAGS
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sStaticVariation.eDeStVarCI  = eDefaultStaticVariationCounterInput.CI_32BIT_WITHFLAG
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sStaticVariation.eDeStVarFzCI= eDefaultStaticVariationFrozenCounterInput.FCI_32BIT_WITHFLAGANDTIME
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sStaticVariation.eDeStVarAI  = eDefaultStaticVariationAnalogInput.AI_SINGLEPREC_FLOATWITHFLAG
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sStaticVariation.eDeStVarFzAI= eDefaultStaticVariationFrozenAnalogInput.FAI_SINGLEPRECFLOATWITHFLAG
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sStaticVariation.eDeStVarAID = eDefaultStaticVariationAnalogInputDeadBand.DAI_SINGLEPRECFLOAT
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sStaticVariation.eDeStVarAO  = eDefaultStaticVariationAnalogOutput.AO_SINGLEPRECFLOAT_WITHFLAG

        # ── Event Variations ──
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sEventVariation.eDeEvVarBI  = eDefaultEventVariationBinaryInput.BIE_WITH_ABSOLUTETIME
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sEventVariation.eDeEvVarDBI = eDefaultEventVariationDoubleBitBinaryInput.DBBIE_WITH_ABSOLUTETIME
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sEventVariation.eDeEvVarCI  = eDefaultEventVariationCounterInput.CIE_32BIT_WITHFLAG_WITHTIME
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sEventVariation.eDeEvVarAI  = eDefaultEventVariationAnalogInput.AIE_SINGLEPREC_WITHTIME
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sEventVariation.eDeEvVarFzCI= eDefaultEventVariationFrozenCounterInput.FCIE_32BIT_WITHFLAG_WITHTIME
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sEventVariation.eDeEvVarFzAI= eDefaultEventVariationFrozenAnalogInput.FAIE_SINGLEPREC_WITHTIME
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sEventVariation.eDeEvVarBO  = eDefaultEventVariationBinaryOutput.BOE_WITH_TIME
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sEventVariation.eDeEvVarAO  = eDefaultEventVariationAnalogOutput.AOE_SINGLEPREC_WITHTIME

        # ── Event Buffers ──
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u16Class1EventBufferSize              = 50
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u8Class1EventBufferOverFlowPercentage = 90
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u16Class2EventBufferSize              = 50
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u8Class2EventBufferOverFlowPercentage = 90
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u16Class3EventBufferSize              = 50
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u8Class3EventBufferOverFlowPercentage = 90

        # ── Timestamp ──
        now = time.time()
        t   = time.localtime(now)
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sTimeStamp.u8Day            = t.tm_mday
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sTimeStamp.u8Month          = t.tm_mon
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sTimeStamp.u16Year          = t.tm_year
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sTimeStamp.u8Hour           = t.tm_hour
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sTimeStamp.u8Minute         = t.tm_min
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sTimeStamp.u8Seconds        = t.tm_sec
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sTimeStamp.u16MilliSeconds  = 0
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sTimeStamp.u16MicroSeconds  = 0
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sTimeStamp.i8DSTTime        = 0
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sTimeStamp.u8DayoftheWeek   = 4
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bTimeInvalid                = False

        # ── Class 0 flags ──
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddBIinClass0   = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddDBIinClass0  = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddBOinClass0   = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddCIinClass0   = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddFzCIinClass0 = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddAIinClass0   = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddFzAIinClass0 = False
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddAIDinClass0  = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddAOinClass0   = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddOSinClass0   = True

        # ── Event flags ──
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddBIEvent  = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddDBIEvent = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddBOEvent  = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddCIEvent  = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddFzCIEvent= True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddAIEvent  = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddFzAIEvent= False
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddAIDEvent = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddAOEvent  = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddOSEvent  = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bAddVTOEvent = True

        # ── Misc Settings ──
        sDNP3Config.sDNP3ServerSet.sServerProtSet.eAIDeadbandMethod          = eAnalogInputDeadbandMethod.DEADBAND_FIXED
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bFrozenAnalogInputSupport  = False
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bEnableSelfAddressSupport  = True
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bEnableFileTransferSupport = False
        sDNP3Config.sDNP3ServerSet.sServerProtSet.u8IntialdatabaseQualityFlag= eDNP3QualityFlags.ONLINE
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bLocalMode                 = False
        sDNP3Config.sDNP3ServerSet.sServerProtSet.bUpdateCheckTimestamp      = False

        # ── Unsolicited ──
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.bEnableUnsolicited        = False
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.bEnableResponsesonStartup = False
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.u32Timeout                = 5000
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.u16Class1TriggerNumberofEvents = 1
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.u16Class1HoldTimeAfterResponse = 1
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.u16Class2TriggerNumberofEvents = 1
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.u16Class2HoldTimeAfterResponse = 1
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.u16Class3TriggerNumberofEvents = 1
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.u16Class3HoldTimeAfterResponse = 1
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.u8Retries              = 5
        sDNP3Config.sDNP3ServerSet.sServerProtSet.sUnsolicitedResponseSet.u16MaxNumberofEvents   = 10

        # ── Debug ──
        sDNP3Config.sDNP3ServerSet.sDebug.u32DebugOptions = (
            eDebugOptionsFlag.DEBUG_OPTION_RX | eDebugOptionsFlag.DEBUG_OPTION_TX
        )

        # ── 4 Data Objects ──
        sDNP3Config.sDNP3ServerSet.u16NoofObject = 4
        sDNP3Config.sDNP3ServerSet.psDNP3Objects = (sDNP3Object * 4)()

        sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].ai8Name              = "binary input 0-9".encode('utf-8')
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].eGroupID             = eDNP3GroupID.BINARY_INPUT
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].u16NoofPoints        = 10
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].eClassID             = eDNP3ClassID.CLASS_ONE
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].eControlModel        = eDNP3ControlModelConfig.INPUT_STATUS_ONLY
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].u32SBOTimeOut        = 0
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].f32AnalogInputDeadband = 0
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[0].eAnalogStoreType     = eAnalogStorageType.AS_FLOAT

        sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].ai8Name              = "analog input 0-9".encode('utf-8')
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].eGroupID             = eDNP3GroupID.ANALOG_INPUT
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].u16NoofPoints        = 10
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].eClassID             = eDNP3ClassID.CLASS_ONE
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].eControlModel        = eDNP3ControlModelConfig.INPUT_STATUS_ONLY
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].u32SBOTimeOut        = 0
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].f32AnalogInputDeadband = 0
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[1].eAnalogStoreType     = eAnalogStorageType.AS_FLOAT

        sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].ai8Name              = "binary output 0-9".encode('utf-8')
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].eGroupID             = eDNP3GroupID.BINARY_OUTPUT
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].u16NoofPoints        = 10
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].eClassID             = eDNP3ClassID.CLASS_ONE
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].eControlModel        = eDNP3ControlModelConfig.DIRECT_OPERATION
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].u32SBOTimeOut        = 0
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].f32AnalogInputDeadband = 0
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[2].eAnalogStoreType     = eAnalogStorageType.AS_FLOAT

        sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].ai8Name              = "analog output 0-9".encode('utf-8')
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].eGroupID             = eDNP3GroupID.ANALOG_OUTPUTS
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].u16NoofPoints        = 10
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].eClassID             = eDNP3ClassID.CLASS_ONE
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].eControlModel        = eDNP3ControlModelConfig.DIRECT_OPERATION
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].u32SBOTimeOut        = 0
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].f32AnalogInputDeadband = 0
        sDNP3Config.sDNP3ServerSet.psDNP3Objects[3].eAnalogStoreType     = eAnalogStorageType.AS_FLOAT

        i16ErrorCode = dnp3_lib.DNP3LoadConfiguration(myServer, ctypes.byref(sDNP3Config), ctypes.byref(tErrorValue))
        if i16ErrorCode != 0:
            print(f"❌ DNP3LoadConfiguration() failed: {errorcodestring(i16ErrorCode)}")
            break
        print("✅ Configuration loaded")

        i16ErrorCode = dnp3_lib.DNP3Start(myServer, ctypes.byref(tErrorValue))
        if i16ErrorCode != 0:
            print(f"❌ DNP3Start() failed: {errorcodestring(i16ErrorCode)}")
            break
        print("✅ DNP3 Outstation running on port 20003... press X to exit")

        while True:
            if keyboard.is_pressed('x'):
                keyboard.release('x')
                break
            time.sleep(0.05)
        break

    dnp3_lib.DNP3Stop(myServer, ctypes.byref(tErrorValue))
    dnp3_lib.DNP3Free(myServer, ctypes.byref(tErrorValue))
    print("🛑 Outstation stopped")

if __name__ == "__main__":
    main()