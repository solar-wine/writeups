#!/usr/bin/env python3
"""Implement the Space Packet protocol as used by cFE for the Software Bus:

https://github.com/nasa/cFE/blob/6.7.3-bv/fsw/cfe-core/src/sb/cfe_sb_msg_id_util.c refers to:

    "CCSDS Space Packet Protocol 133.0.B-1 with Technical Corrigendum 2, September 2012"

So the relevant specifications are:
* https://public.ccsds.org/Pubs/133x0b1c2.pdf
  CCSDS Space Packet Protocol 133.0.B-1
* https://public.ccsds.org/Pubs/133x0b1c2_tc1227.pdf
  Space Packet Protocol Technical Corrigendum 2, September 2012
"""
import IPython
import argparse
import time
import binascii

from scapy.all import *


# APID names according to "That's not on my calendar" challenge
# find /src -name unit_test -prune -o -name examples -prune -o \
#   -name '*.h' -exec cat {} + | \
#   sed -n 's/^\s*#define\s*\(\S*\)_MID\s.*\(0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]\).*/\1 = \2/p' | \
#   sort -u | sort -k3
APID_NAMES = {
    # CMD
    1: {
        0x001: "CFE_EVS_CMD",  # CFE_EVS_CMD_MID = 0x1801
        0x002: "ISIM_CMD",  # ISIM_CMD_MID = 0x1802
        0x003: "CFE_SB_CMD",  # CFE_SB_CMD_MID = 0x1803
        0x004: "CFE_TBL_CMD",  # CFE_TBL_CMD_MID = 0x1804
        0x005: "CFE_TIME_CMD",  # CFE_TIME_CMD_MID = 0x1805
        0x006: "CFE_ES_CMD",  # CFE_ES_CMD_MID = 0x1806
        0x008: "CFE_ES_SEND_HK",  # CFE_ES_SEND_HK_MID = 0x1808
        0x009: "CFE_EVS_SEND_HK",  # CFE_EVS_SEND_HK_MID = 0x1809
        0x00b: "CFE_SB_SEND_HK",  # CFE_SB_SEND_HK_MID = 0x180b
        0x00c: "CFE_TBL_SEND_HK",  # CFE_TBL_SEND_HK_MID = 0x180c
        0x00d: "CFE_TIME_SEND_HK",  # CFE_TIME_SEND_HK_MID = 0x180d
        0x010: "CFE_TIME_TONE_CMD",  # CFE_TIME_TONE_CMD_MID = 0x1810
        0x011: "CFE_TIME_1HZ_CMD",  # CFE_TIME_1HZ_CMD_MID = 0x1811
        0x060: "CFE_TIME_DATA_CMD",  # CFE_TIME_DATA_CMD_MID = 0x1860
        0x062: "CFE_TIME_SEND_CMD",  # CFE_TIME_SEND_CMD_MID = 0x1862
        0x066: "OSK_DEMO_CMD",  # OSK_DEMO_CMD_MID = 0x1866
        0x080: "KIT_TO_CMD",  # KIT_TO_CMD_MID = 0x1880
        0x081: "KIT_TO_SEND_HK",  # KIT_TO_SEND_HK_MID = 0x1881
        0x082: "KIT_TO_SEND_FLAG",  # KIT_TO_SEND_FLAG_MID = 0x1882
        0x084: "KIT_CI_CMD",  # KIT_CI_CMD_MID = 0x1884
        0x085: "KIT_CI_SEND_HK",  # KIT_CI_SEND_HK_MID = 0x1885
        0x088: "MM_CMD",  # MM_CMD_MID = 0x1888
        0x089: "MM_SEND_HK",  # MM_SEND_HK_MID = 0x1889
        0x08c: "FM_CMD",  # FM_CMD_MID = 0x188c
        0x08d: "FM_SEND_HK",  # FM_SEND_HK_MID = 0x188d
        0x090: "MD_CMD",  # MD_CMD_MID = 0x1890
        0x091: "MD_SEND_HK",  # MD_SEND_HK_MID = 0x1891
        0x092: "MD_WAKEUP",  # MD_WAKEUP_MID = 0x1892
        0x095: "KIT_SCH_CMD",  # KIT_SCH_CMD_MID = 0x1895
        0x096: "KIT_SCH_SEND_HK",  # KIT_SCH_SEND_HK_MID = 0x1896
        0x09a: "HK_CMD",  # HK_CMD_MID = 0x189a
        0x09b: "HK_SEND_HK",  # HK_SEND_HK_MID = 0x189b
        0x09c: "HK_SEND_COMBINED_PKT",  # HK_SEND_COMBINED_PKT_MID = 0x189c
        0x09f: "CS_CMD",  # CS_CMD_MID = 0x189f
        0x0a0: "CS_SEND_HK",  # CS_SEND_HK_MID = 0x18a0
        0x0a1: "CS_BACKGROUND_CYCLE",  # CS_BACKGROUND_CYCLE_MID = 0x18a1
        0x0a4: "LC_CMD",  # LC_CMD_MID = 0x18a4
        0x0a5: "LC_SEND_HK",  # LC_SEND_HK_MID = 0x18a5
        0x0a6: "LC_SAMPLE_AP",  # LC_SAMPLE_AP_MID = 0x18a6
        # 0x0a9: "LC_RTS_REQ",  # LC_RTS_REQ_MID = 0x18a9  # Duplicate?
        0x0a9: "SC_CMD",  # SC_CMD_MID = 0x18a9
        0x0aa: "SC_SEND_HK",  # SC_SEND_HK_MID = 0x18aa
        0x0ab: "SC_1HZ_WAKEUP",  # SC_1HZ_WAKEUP_MID = 0x18ab
        0x0ae: "HS_CMD",  # HS_CMD_MID = 0x18ae
        0x0af: "HS_SEND_HK",  # HS_SEND_HK_MID = 0x18af
        0x0b0: "HS_WAKEUP",  # HS_WAKEUP_MID = 0x18b0
        0x0b3: "CF_CMD",  # CF_CMD_MID = 0x18b3
        0x0b4: "CF_SEND_HK",  # CF_SEND_HK_MID = 0x18b4
        0x0b5: "CF_WAKE_UP_REQ_CMD",  # CF_WAKE_UP_REQ_CMD_MID = 0x18b5
        0x0b6: "CF_SPARE1_CMD",  # CF_SPARE1_CMD_MID = 0x18b6
        0x0b7: "CF_SPARE2_CMD",  # CF_SPARE2_CMD_MID = 0x18b7
        0x0b8: "CF_SPARE3_CMD",  # CF_SPARE3_CMD_MID = 0x18b8
        0x0b9: "CF_SPARE4_CMD",  # CF_SPARE4_CMD_MID = 0x18b9
        0x0ba: "CF_SPARE5_CMD",  # CF_SPARE5_CMD_MID = 0x18ba
        0x0bb: "DS_CMD",  # DS_CMD_MID = 0x18bb
        0x0bc: "DS_SEND_HK",  # DS_SEND_HK_MID = 0x18bc
        0x0fa: "SBN_CMD",  # SBN_CMD_MID = 0x18fa
        0x100: "TFTP_CMD",  # TFTP_CMD_MID = 0x1900
        0x101: "TFTP_SEND_HK",  # TFTP_SEND_HK_MID = 0x1901
        0x1a5: "HC_CMD",  # HC_CMD_MID = 0x19a5
        0x1b1: "SIM_CMD",  # SIM_CMD_MID = 0x19b1
        0x1b2: "SIM_SEND_HK",  # SIM_SEND_HK_MID = 0x19b2
        0x1b3: "SIM_SEND_DATA",  # SIM_SEND_DATA_MID = 0x19b3
        0x1b4: "SIM_HC_DATA",  # SIM_HC_DATA_MID = 0x19b4
        0x1ba: "HC_SEND_HK",  # HC_SEND_HK_MID = 0x19ba
        0x1c1: "HC_01HZ_WAKEUP",  # HC_01HZ_WAKEUP_MID = 0x19c1
        0x1d0: "F42_CMD",  # F42_CMD_MID = 0x19d0
        0x1d1: "F42_SEND_HK",  # F42_SEND_HK_MID = 0x19d1
        0x1d2: "I42_CMD",  # I42_CMD_MID = 0x19d2
        0x1d3: "I42_SEND_HK",  # I42_SEND_HK_MID = 0x19d3
        0x1d4: "EYASSAT_IF_SEND_HK",  # EYASSAT_IF_SEND_HK_MID = 0x19d4
        0x1d5: "EYASSAT_IF_CMD",  # EYASSAT_IF_CMD_MID = 0x19d5
        0x1f0: "BM_CMD",  # BM_CMD_MID = 0x19f0
        0x1f1: "BM_SEND_HK",  # BM_SEND_HK_MID = 0x19f1
        0x1f2: "BM_WAKEUP",  # BM_WAKEUP_MID = 0x19f2
        0x1f3: "BM_OUT_DATA",  # BM_OUT_DATA_MID = 0x19f3
        0x1f4: "BM_CREATE_CHILD_TASK",  # BM_CREATE_CHILD_TASK_MID = 0x19f4
        0x1f5: "BM_UNLOCK_PARAMS",  # BM_UNLOCK_PARAMS_MID = 0x19f5
        0x7fc: "LTP over space packets",
        0x7fd: "CF_INCOMING_PDU (CFDP)",  # CF_INCOMING_PDU_MID = 0x1ffd
    },
    # TLM
    0: {
        0x000: "CFE_ES_HK_TLM",  # CFE_ES_HK_TLM_MID = 0x0800
        0x001: "CFE_EVS_HK_TLM",  # CFE_EVS_HK_TLM_MID = 0x0801
        0x003: "CFE_SB_HK_TLM",  # CFE_SB_HK_TLM_MID = 0x0803
        0x004: "CFE_TBL_HK_TLM",  # CFE_TBL_HK_TLM_MID = 0x0804
        0x005: "CFE_TIME_HK_TLM",  # CFE_TIME_HK_TLM_MID = 0x0805
        0x006: "CFE_TIME_DIAG_TLM",  # CFE_TIME_DIAG_TLM_MID = 0x0806
        0x008: "CFE_EVS_LONG_EVENT_MSG",  # CFE_EVS_LONG_EVENT_MSG_MID = 0x0808
        0x009: "CFE_EVS_SHORT_EVENT_MSG",  # CFE_EVS_SHORT_EVENT_MSG_MID = 0x0809
        0x00a: "CFE_SB_STATS_TLM",  # CFE_SB_STATS_TLM_MID = 0x080a
        0x00b: "CFE_ES_APP_TLM",  # CFE_ES_APP_TLM_MID = 0x080b
        0x00c: "CFE_TBL_REG_TLM",  # CFE_TBL_REG_TLM_MID = 0x080c
        0x00d: "CFE_SB_ALLSUBS_TLM",  # CFE_SB_ALLSUBS_TLM_MID = 0x080d
        0x00e: "CFE_SB_ONESUB_TLM",  # CFE_SB_ONESUB_TLM_MID = 0x080e
        0x00f: "CFE_ES_SHELL_TLM",  # CFE_ES_SHELL_TLM_MID = 0x080f
        0x010: "CFE_ES_MEMSTATS_TLM",  # CFE_ES_MEMSTATS_TLM_MID = 0x0810
        0x080: "KIT_TO_HK_TLM",  # KIT_TO_HK_TLM_MID = 0x0880
        0x081: "KIT_TO_DATA_TYPE_TLM",  # KIT_TO_DATA_TYPE_TLM_MID = 0x0881
        0x082: "ISIM_TLM_HK",  # ISIM_TLM_HK_MID = 0x0882
        0x084: "KIT_CI_HK_TLM",  # KIT_CI_HK_TLM_MID = 0x0884
        0x086: "KIT_TO_FLAG_TLM",  # KIT_TO_FLAG_TLM_MID = 0x0886
        0x087: "MM_HK_TLM",  # MM_HK_TLM_MID = 0x0887
        0x08a: "FM_HK_TLM",  # FM_HK_TLM_MID = 0x088a
        0x08b: "FM_FILE_INFO_TLM",  # FM_FILE_INFO_TLM_MID = 0x088b
        0x08c: "FM_DIR_LIST_TLM",  # FM_DIR_LIST_TLM_MID = 0x088c
        0x08d: "FM_OPEN_FILES_TLM",  # FM_OPEN_FILES_TLM_MID = 0x088d
        0x08e: "FM_FREE_SPACE_TLM",  # FM_FREE_SPACE_TLM_MID = 0x088e
        0x090: "MD_HK_TLM",  # MD_HK_TLM_MID = 0x0890
        0x099: "KIT_SCH_HK_TLM",  # KIT_SCH_HK_TLM_MID = 0x0899
        0x09b: "HK_HK_TLM",  # HK_HK_TLM_MID = 0x089b
        0x09c: "HK_COMBINED_PKT1",  # HK_COMBINED_PKT1_MID = 0x089c
        0x09d: "HK_COMBINED_PKT2",  # HK_COMBINED_PKT2_MID = 0x089d
        0x09e: "HK_COMBINED_PKT3",  # HK_COMBINED_PKT3_MID = 0x089e
        0x09f: "HK_COMBINED_PKT4",  # HK_COMBINED_PKT4_MID = 0x089f
        0x0a4: "CS_HK_TLM",  # CS_HK_TLM_MID = 0x08a4
        0x0a7: "LC_HK_TLM",  # LC_HK_TLM_MID = 0x08a7
        0x0aa: "SC_HK_TLM",  # SC_HK_TLM_MID = 0x08aa
        0x0ad: "HS_HK_TLM",  # HS_HK_TLM_MID = 0x08ad
        0x0b0: "CF_HK_TLM",  # CF_HK_TLM_MID = 0x08b0
        0x0b1: "CF_TRANS_TLM",  # CF_TRANS_TLM_MID = 0x08b1
        0x0b2: "CF_CONFIG_TLM",  # CF_CONFIG_TLM_MID = 0x08b2
        0x0b3: "CF_SPARE0_TLM",  # CF_SPARE0_TLM_MID = 0x08b3
        0x0b4: "CF_SPARE1_TLM",  # CF_SPARE1_TLM_MID = 0x08b4
        0x0b5: "CF_SPARE2_TLM",  # CF_SPARE2_TLM_MID = 0x08b5
        0x0b6: "CF_SPARE3_TLM",  # CF_SPARE3_TLM_MID = 0x08b6
        0x0b7: "CF_SPARE4_TLM",  # CF_SPARE4_TLM_MID = 0x08b7
        0x0b8: "DS_HK_TLM",  # DS_HK_TLM_MID = 0x08b8
        0x0b9: "DS_DIAG_TLM",  # DS_DIAG_TLM_MID = 0x08b9
        0x0fc: "SBN_TLM",  # SBN_TLM_MID = 0x08fc
        0x100: "TFTP_HK_TLM",  # TFTP_HK_TLM_MID = 0x0900
        0x1b1: "SIM_HK_TLM",  # SIM_HK_TLM_MID = 0x09b1
        0x1d0: "F42_HK_TLM",  # F42_HK_TLM_MID = 0x09d0
        0x1d1: "F42_CONTROL",  # F42_CONTROL_MID = 0x09d1
        0x1d2: "I42_HK_TLM",  # I42_HK_TLM_MID = 0x09d2
        0x1d4: "EYASSAT_IF_TLM_HK",  # EYASSAT_IF_TLM_HK_MID = 0x09d4
        0x1d5: "EYASSAT_IF_TLM_INTERNAL",  # EYASSAT_IF_TLM_INTERNAL_MID = 0x09d5
        0x1d6: "EYASSAT_IF_TLM_TEMP",  # EYASSAT_IF_TLM_TEMP_MID = 0x09d6
        0x1d7: "EYASSAT_IF_TLM_POWER",  # EYASSAT_IF_TLM_POWER_MID = 0x09d7
        0x1d8: "EYASSAT_IF_TLM_UNSCALED_POWER",  # EYASSAT_IF_TLM_UNSCALED_POWER_MID = 0x09d8
        0x1d9: "EYASSAT_IF_TLM_ADCS",  # EYASSAT_IF_TLM_ADCS_MID = 0x09d9
        0x1e0: "F42_SENSOR",  # F42_SENSOR_MID = 0x09e0
        0x1e1: "F42_ACTUATOR",  # F42_ACTUATOR_MID = 0x09e1
        0x1f0: "BM_HK_TLM",  # BM_HK_TLM_MID = 0x09f0
        0x1f1: "BM_TST",  # BM_TST_MID = 0x09f1
        0x1f2: "BM_CHLD",  # BM_CHLD_MID = 0x09f2
        0x240: "HC_HK_TLM",  # HC_HK_TLM_MID = 0x0a40
        0x241: "HC_THERM_TLM",  # HC_THERM_TLM_MID = 0x0a41
        0x703: "OSK_DEMO_TLM_HK",  # OSK_DEMO_TLM_HK_MID = 0x0f03
        0x704: "OSK_DEMO_TLM_FR",  # OSK_DEMO_TLM_FR_MID = 0x0f04
        0x7fc: "LTP over space packets",
        0x7fd: "CF_SPACE_TO_GND_PDU (CFDP)",  # CF_SPACE_TO_GND_PDU_MID = 0x0ffd
    },
}


class CCSDSPacket(Packet):
    """CCSDS Space packet

    Structures from https://github.com/nasa/cFE/blob/6.7.3-bv/fsw/cfe-core/src/inc/ccsds.h:
        struct CCSDS_PriHdr_t {
            uint16be StreamId;
            uint16be Sequence;
            uint16be Length;
        }
        struct CCSDS_CmdSecHdr_t { // Secondary header for commands
            uint16be Command
        }
        struct CCSDS_TlmSecHdr_t { // Secondary header for telemetry
            uint8  Time[CCSDS_TIME_SIZE];
        }
    """
    name = "CCSDS"
    fields_desc = [
        # CCSDS version = StreamId & 0xe000
        # Version number from https://sanaregistry.org/r/packet_version_number
        # value 0 means "version 1"
        BitEnumField("version", 0, 3, {0: "#1"}),

        # packet type = StreamId & 0x1000
        BitEnumField("pkttype", 1, 1, {0: "TLM", 1: "CMD"}),

        # secondary header present = StreamId & 0x0800
        # Always present of command packets
        BitField("has_sec_header", 1, 1),

        # APID (CCSDS Application ID) = StreamId & 0x07ff
        # https://sanaregistry.org/r/space_packet_protocol_application_process_id
        BitMultiEnumField("apid", 0, 11, APID_NAMES, depends_on=lambda pkt: pkt.pkttype),

        # segmentation flags = Sequence & 0xc000
        # 3 means complete packet (0=continuation, 1=first, 2=last)
        BitField("segm_flags", 3, 2),

        # sequence count = Sequence & 0x3fff
        XBitField("seq_count", 0, 14),

        # packet length word
        ShortField("pkt_length", None),

        # Skip CCSDS_APIDqualifiers_t if MESSAGE_FORMAT_IS_CCSDS_VER_2

        # command function code (high bit is reserved) = Command & 0xff00
        ConditionalField(ByteField("cmd_func_code", 0),
                         lambda pkt: pkt.pkttype == 1 and pkt.has_sec_header),
        # XOR-to-0xff checksum = Command & 0x00ff
        ConditionalField(ByteField("cmd_checksum", 0),
                         lambda pkt: pkt.pkttype == 1 and pkt.has_sec_header),

        # Telemetry time: 32 bits seconds
        ConditionalField(IntField("tlm_time_secs", 0),
                         lambda pkt: pkt.pkttype == 0 and pkt.has_sec_header),
        # Telemetry time: 16 bits subseconds
        ConditionalField(ShortField("tlm_time_subsecs", 0),
                         lambda pkt: pkt.pkttype == 0 and pkt.has_sec_header),
    ]

    def post_build(self, pkt, payload):
        if payload:
            pkt += payload
        # Update length
        if self.pkt_length is None:
            pkt_length = len(pkt) - 7
            pkt = pkt[:4] + pkt_length.to_bytes(2, 'big') + pkt[6:]
        # Update checksum
        if self.pkttype == 1 and self.has_sec_header:
            cksum = 0xff
            for idx, x in enumerate(pkt):
                if idx != 7:
                    cksum ^= x
            pkt = pkt[:7] + cksum.to_bytes(1, 'big') + pkt[8:]
        return pkt


class CFE_ES_HkTlmPkt(Packet):
    """cFE Executive Service Housekeeping TLM Packet"""
    name = "CFE_ES_HkTlmPkt"
    fields_desc = [
        ByteField("CommandCounter", 0),  # ES_CMDPC
        ByteField("CommandErrorCounter", 0),  # ES_CMDEC
        LEShortField("CFECoreChecksum", 0),  # ES_CKSUM
        ByteField("CFEMajorVersion", 0),  # ES_CFEMAJORVER
        ByteField("CFEMinorVersion", 0),  # ES_CFEMINORVER
        ByteField("CFERevision", 0),  # ES_CFEREVISION
        ByteField("CFEMissionRevision", 0),  # ES_CFEMISSIONREV
        ByteField("OSALMajorVersion", 0),  # ES_OSMAJORVER
        ByteField("OSALMinorVersion", 0),  # ES_OSMINORVER
        ByteField("OSALRevision", 0),  # ES_OSREVISION
        ByteField("OSALMissionRevision", 0),  # ES_OSMISSIONREV
        LEIntField("SysLogBytesUsed", 0),  # ES_SYSLOGBYTEUSED
        LEIntField("SysLogSize", 0),  # ES_SYSLOGSIZE
        LEIntField("SysLogEntries", 0),  # ES_SYSLOGENTRIES
        LEIntField("SysLogMode", 0),  # ES_SYSLOGMODE
        LEIntField("ERLogIndex", 0),  # ES_ERLOGINDEX
        LEIntField("ERLogEntries", 0),  # ES_ERLOGENTRIES
        LEIntField("RegisteredCoreApps", 0),  # ES_REGCOREAPPS
        LEIntField("RegisteredExternalApps", 0),  # ES_REGEXTAPPS
        LEIntField("RegisteredTasks", 0),  # ES_REGTASKS
        LEIntField("RegisteredLibs", 0),  # ES_REGLIBS
        LEIntField("ResetType", 0),  # ES_RESETTYPE
        LEIntField("ResetSubtype", 0),  # ES_RESETSUBTYPE
        LEIntField("ProcessorResets", 0),  # ES_PROCRESETCNT
        LEIntField("MaxProcessorResets", 0),  # ES_MAXPROCRESETS
        LEIntField("BootSource", 0),  # ES_BOOTSOURCE
        LEIntField("PerfState", 0),  # ES_PERFSTATE
        LEIntField("PerfMode", 0),  # ES_PERFMODE
        LEIntField("PerfTriggerCount", 0),  # ES_PERFTRIGCNT
        # Assume CFE_MISSION_ES_PERF_MAX_IDS = 128 = 4 uint32
        FieldListField("PerfFilterMask", [], XLEIntField("", 0), count_from=lambda pkt: 4),  # ES_PERFFLTRMASK
        FieldListField("PerfTriggerMask", [], XLEIntField("", 0), count_from=lambda pkt: 4),  # ES_PERFTRIGMASK
        LEIntField("PerfDataStart", 0),  # ES_PERFDATASTART
        LEIntField("PerfDataEnd", 0),  # ES_PERFDATAEND
        LEIntField("PerfDataCount", 0),  # ES_PERFDATACNT
        LEIntField("PerfDataToWrite", 0),  # ES_PERFDATA2WRITE
        LEIntField("HeapBytesFree", 0),  # ES_HEAPBYTESFREE
        LEIntField("HeapBlocksFree", 0),  # ES_HEAPBLKSFREE
        LEIntField("HeapMaxBlockSize", 0),  # ES_HEAPMAXBLK
    ]


bind_layers(CCSDSPacket, CFE_ES_HkTlmPkt, pkttype=0, apid=0x000)


class CFE_EVS_HkTlmPkt(Packet):
    """cFE Event Service Housekeeping TLM Packet"""
    name = "CFE_EVS_HkTlmPkt"
    fields_desc = [
        ByteField("CommandCounter", 0),  # EVS_CMDPC
        ByteField("CommandErrorCounter", 0),  # EVS_CMDEC
        ByteField("MessageFormatMode", 0),  # EVS_MSGFMTMODE
        ByteField("MessageTruncCounter", 0),  # EVS_MSGTRUNC
        ByteField("UnregisteredAppCounter", 0),  # EVS_UNREGAPPC
        ByteField("OutputPort", 0),  # EVS_OUTPUTPORT
        ByteField("LogFullFlag", 0),  # EVS_LOGFULL
        ByteField("LogMode", 0),  # EVS_LOGMODE
        LEShortField("MessageSendCounter", 0),  # EVS_MSGSENTC
        LEShortField("LogOverflowCounter", 0),  # EVS_LOGOVERFLOWC
        ByteField("LogEnabled", 0),  # EVS_LOGENABLED
        ByteField("Spare1", 0),  # EVS_HK_SPARE1
        ByteField("Spare2", 0),  # EVS_HK_SPARE2
        ByteField("Spare3", 0),  # EVS_HK_SPARE3
        # FieldListField("AppData", [], ByteField("", 0)),  # EVS_APP
        XLEIntField("AppID_0", 0),  # EVS_APPID for AppData[0]
        LEShortField("AppMessageSentCounter_0", 0),  # EVS_APPMSGSENTC for AppData[0]
        ByteField("AppEnableStatus_0", 0),  # EVS_APPENASTAT for AppData[0]
        ByteField("Padding_0", 0),  # EVS_SPARE2ALIGN3 for AppData[0]
        XLEIntField("AppID_1", 0),  # EVS_APPID for AppData[1]
        LEShortField("AppMessageSentCounter_1", 0),  # EVS_APPMSGSENTC for AppData[1]
        ByteField("AppEnableStatus_1", 0),  # EVS_APPENASTAT for AppData[1]
        ByteField("Padding_1", 0),  # EVS_SPARE2ALIGN3 for AppData[1]
        XLEIntField("AppID_2", 0),  # EVS_APPID for AppData[2]
        LEShortField("AppMessageSentCounter_2", 0),  # EVS_APPMSGSENTC for AppData[2]
        ByteField("AppEnableStatus_2", 0),  # EVS_APPENASTAT for AppData[2]
        ByteField("Padding_2", 0),  # EVS_SPARE2ALIGN3 for AppData[2]
        XLEIntField("AppID_3", 0),  # EVS_APPID for AppData[3]
        LEShortField("AppMessageSentCounter_3", 0),  # EVS_APPMSGSENTC for AppData[3]
        ByteField("AppEnableStatus_3", 0),  # EVS_APPENASTAT for AppData[3]
        ByteField("Padding_3", 0),  # EVS_SPARE2ALIGN3 for AppData[3]
        XLEIntField("AppID_4", 0),  # EVS_APPID for AppData[4]
        LEShortField("AppMessageSentCounter_4", 0),  # EVS_APPMSGSENTC for AppData[4]
        ByteField("AppEnableStatus_4", 0),  # EVS_APPENASTAT for AppData[4]
        ByteField("Padding_4", 0),  # EVS_SPARE2ALIGN3 for AppData[4]
        XLEIntField("AppID_5", 0),  # EVS_APPID for AppData[5]
        LEShortField("AppMessageSentCounter_5", 0),  # EVS_APPMSGSENTC for AppData[5]
        ByteField("AppEnableStatus_5", 0),  # EVS_APPENASTAT for AppData[5]
        ByteField("Padding_5", 0),  # EVS_SPARE2ALIGN3 for AppData[5]
        XLEIntField("AppID_6", 0),  # EVS_APPID for AppData[6]
        LEShortField("AppMessageSentCounter_6", 0),  # EVS_APPMSGSENTC for AppData[6]
        ByteField("AppEnableStatus_6", 0),  # EVS_APPENASTAT for AppData[6]
        ByteField("Padding_6", 0),  # EVS_SPARE2ALIGN3 for AppData[6]
        XLEIntField("AppID_7", 0),  # EVS_APPID for AppData[7]
        LEShortField("AppMessageSentCounter_7", 0),  # EVS_APPMSGSENTC for AppData[7]
        ByteField("AppEnableStatus_7", 0),  # EVS_APPENASTAT for AppData[7]
        ByteField("Padding_7", 0),  # EVS_SPARE2ALIGN3 for AppData[7]
        XLEIntField("AppID_8", 0),  # EVS_APPID for AppData[8]
        LEShortField("AppMessageSentCounter_8", 0),  # EVS_APPMSGSENTC for AppData[8]
        ByteField("AppEnableStatus_8", 0),  # EVS_APPENASTAT for AppData[8]
        ByteField("Padding_8", 0),  # EVS_SPARE2ALIGN3 for AppData[8]
        XLEIntField("AppID_9", 0),  # EVS_APPID for AppData[9]
        LEShortField("AppMessageSentCounter_9", 0),  # EVS_APPMSGSENTC for AppData[9]
        ByteField("AppEnableStatus_9", 0),  # EVS_APPENASTAT for AppData[9]
        ByteField("Padding_9", 0),  # EVS_SPARE2ALIGN3 for AppData[9]
        XLEIntField("AppID_10", 0),  # EVS_APPID for AppData[10]
        LEShortField("AppMessageSentCounter_10", 0),  # EVS_APPMSGSENTC for AppData[10]
        ByteField("AppEnableStatus_10", 0),  # EVS_APPENASTAT for AppData[10]
        ByteField("Padding_10", 0),  # EVS_SPARE2ALIGN3 for AppData[10]
        XLEIntField("AppID_11", 0),  # EVS_APPID for AppData[11]
        LEShortField("AppMessageSentCounter_11", 0),  # EVS_APPMSGSENTC for AppData[11]
        ByteField("AppEnableStatus_11", 0),  # EVS_APPENASTAT for AppData[11]
        ByteField("Padding_11", 0),  # EVS_SPARE2ALIGN3 for AppData[11]
        XLEIntField("AppID_12", 0),  # EVS_APPID for AppData[12]
        LEShortField("AppMessageSentCounter_12", 0),  # EVS_APPMSGSENTC for AppData[12]
        ByteField("AppEnableStatus_12", 0),  # EVS_APPENASTAT for AppData[12]
        ByteField("Padding_12", 0),  # EVS_SPARE2ALIGN3 for AppData[12]
        XLEIntField("AppID_13", 0),  # EVS_APPID for AppData[13]
        LEShortField("AppMessageSentCounter_13", 0),  # EVS_APPMSGSENTC for AppData[13]
        ByteField("AppEnableStatus_13", 0),  # EVS_APPENASTAT for AppData[13]
        ByteField("Padding_13", 0),  # EVS_SPARE2ALIGN3 for AppData[13]
        XLEIntField("AppID_14", 0),  # EVS_APPID for AppData[14]
        LEShortField("AppMessageSentCounter_14", 0),  # EVS_APPMSGSENTC for AppData[14]
        ByteField("AppEnableStatus_14", 0),  # EVS_APPENASTAT for AppData[14]
        ByteField("Padding_14", 0),  # EVS_SPARE2ALIGN3 for AppData[14]
        XLEIntField("AppID_15", 0),  # EVS_APPID for AppData[15]
        LEShortField("AppMessageSentCounter_15", 0),  # EVS_APPMSGSENTC for AppData[15]
        ByteField("AppEnableStatus_15", 0),  # EVS_APPENASTAT for AppData[15]
        ByteField("Padding_15", 0),  # EVS_SPARE2ALIGN3 for AppData[15]
    ]


bind_layers(CCSDSPacket, CFE_EVS_HkTlmPkt, pkttype=0, apid=0x001)


class CFE_SB_HkTlmPkt(Packet):
    """cFE Software Bus Service Housekeeping TLM Packet"""
    name = "CFE_SB_HkTlmPkt"
    fields_desc = [
        ByteField("CommandCounter", 0),  # SB_CMDPC
        ByteField("CommandErrorCounter", 0),  # SB_CMDEC
        ByteField("NoSubscribersCounter", 0),  # SB_NOSUBEC
        ByteField("MsgSendErrorCounter", 0),  # SB_MSGSNDEC
        ByteField("MsgReceiveErrorCounter", 0),  # SB_MSGRECEC
        ByteField("InternalErrorCounter", 0),  # SB_INTERNALEC
        ByteField("CreatePipeErrorCounter", 0),  # SB_NEWPIPEEC
        ByteField("SubscribeErrorCounter", 0),  # SB_SUBSCREC
        ByteField("PipeOptsErrorCounter", 0),  # SB_PIPEOPTSEC
        ByteField("DuplicateSubscriptionsCounter", 0),  # SB_DUPSUBCNT
        LEShortField("Spare2Align", 0),  # SB_SPARE2ALIGN
        LEShortField("PipeOverflowErrorCounter", 0),  # SB_PIPEOVREC
        LEShortField("MsgLimitErrorCounter", 0),  # SB_MSGLIMEC
        XLEIntField("MemPoolHandle", 0),  # SB_MEMPOOLHANDLE, Assuming 32-bit Little Endian CPU
        LEIntField("MemInUse", 0),  # SB_MEMINUSE
        LEIntField("UnmarkedMem", 0),  # SB_UNMARKEDMEM
    ]


bind_layers(CCSDSPacket, CFE_SB_HkTlmPkt, pkttype=0, apid=0x003)


class CFE_TBL_HkTlmPkt(Packet):
    """cFE Table Service Housekeeping TLM Packet"""
    name = "CFE_TBL_HkTlmPkt"
    fields_desc = [
        # Task command interface counters
        ByteField("CommandCounter", 0),  # TBL_CMDPC
        ByteField("CommandErrorCounter", 0),  # TBL_CMDEC
        # Table Registry Statistics
        LEShortField("NumTables", 0),  # TBL_NUMTABLES
        LEShortField("NumLoadPending", 0),  # TBL_NUMUPDATESPEND
        # Last Table Validation Results
        LEShortField("ValidationCounter", 0),  # TBL_VALCOMPLTDCTR
        XLEIntField("LastValCrc", 0),  # TBL_LASTVALCRC
        XLEIntField("LastValStatus", 0),  # TBL_LASTVALS
        ByteField("ActiveBuffer", 0),  # TBL_LASTVALBUF
        StrFixedLenField("LastValTableName", b"", 40),  # TBL_LASTVALTBLNAME[CFE_MISSION_TBL_MAX_FULL_NAME_LEN=16+20+4]
        ByteField("SuccessValCounter", 0),  # TBL_VALSUCCESSCTR
        ByteField("FailedValCounter", 0),  # TBL_VALFAILEDCTR
        ByteField("NumValRequests", 0),  # TBL_VALREQCTR
        # Ground system interface information
        ByteField("NumFreeSharedBufs", 0),  # TBL_NUMFREESHRBUF
        StrFixedLenField("_padding", b"", 3),  # TBL_BYTEALIGNPAD1
        XLEIntField("MemPoolHandle", 0),  # TBL_MEMPOOLHANDLE, Assuming 32-bit Little Endian CPU
        LEIntField("LastUpdateTime_Seconds", 0),  # TBL_LASTUPDTIME
        LEIntField("LastUpdateTime_Subseconds", 0),
        StrFixedLenField("LastUpdatedTable", b"", 40),  # TBL_LASTUPDTBLNAME[CFE_MISSION_TBL_MAX_FULL_NAME_LEN]
        StrFixedLenField("LastFileLoaded", b"", 64),  # TBL_LASTFILELOADED[CFE_MISSION_MAX_PATH_LEN = 64]
        StrFixedLenField("LastFileDumped", b"", 64),  # TBL_LASTFILEDUMPED[CFE_MISSION_MAX_PATH_LEN]
        StrFixedLenField("LastTableLoaded", b"", 40),  # TBL_LASTTABLELOADED[CFE_MISSION_TBL_MAX_FULL_NAME_LEN]
    ]


bind_layers(CCSDSPacket, CFE_TBL_HkTlmPkt, pkttype=0, apid=0x004)


class CFE_TIME_HkTlmPkt(Packet):
    """cFR Time Service Housekeeping TLM Packet"""
    name = "CFE_TIME_HkTlmPkt"
    fields_desc = [
        # Task command interface counters
        ByteField("CommandCounter", 0),  # TIME_CMDPC
        ByteField("CommandErrorCounter", 0),  # TIME_CMDEC
        # Clock state flags and "as calculated" clock state
        LEShortField("ClockStateFlags", 0),  # TIME_STATEFLG
        LEShortField("ClockStateAPI", 0),  # TIME_APISTATE
        # Leap Seconds
        LEShortField("LeapSeconds", 0),  # TIME_LEAPSECS
        # Current MET and STCF time values
        LEIntField("SecondsMET", 0),  # TIME_METSECS
        LEIntField("SubsecsMET", 0),  # TIME_METSUBSECS
        LEIntField("SecondsSTCF", 0),  # TIME_STCFSECS
        LEIntField("SubsecsSTCF", 0),  # TIME_STCFSUBSECS
        # 1Hz STCF adjustment values (server only)...
        LEIntField("Seconds1HzAdj", 0),  # TIME_1HZADJSECS
        LEIntField("Subsecs1HzAdj", 0),  # TIME_1HZADJSSECS
    ]


bind_layers(CCSDSPacket, CFE_TIME_HkTlmPkt, pkttype=0, apid=0x005)


class CFE_EVS_LongEventMsg(Packet):
    """cFE Event Service: Long Event Message (CFE_EVS_LONG_EVENT_MSG)

    Structure CFE_EVS_LongEventTlm_Payload_t field by function
    EVS_GenerateEventTelemetry(), called by CFE_EVS_SendEvent().
    """
    name = "CFE_EVS_LongEventMsg"
    fields_desc = [
        # Packet ID
        StrFixedLenField("AppName", b"", 20),  # EVS_APPNAME[CFE_MISSION_MAX_API_LEN = 20]
        LEShortField("EventID", 0),  # EVS_EVENTID
        LEShortField("EventType", 0),  # EVS_EVENTTYPE
        XLEIntField("SpacecraftID", 0),  # EVS_SCID
        LEIntField("ProcessorID", 0),  # EVS_PROCESSORID
        StrFixedLenField("Message", b"", 124),  # EVS_EVENT[CFE_MISSION_EVS_MAX_MESSAGE_LENGTH = 122] + spare[2]
    ]


bind_layers(CCSDSPacket, CFE_EVS_LongEventMsg, pkttype=0, apid=0x008)


class KIT_TO_HkTlmPkt(Packet):
    """KIT Telemetry Output Housekeeping TLM Packet"""
    name = "KIT_TO_HkTlmPkt"
    fields_desc = [
        # CMDMGR Data
        LEShortField("ValidCmdCnt", 0),
        LEShortField("InvalidCmdCnt", 0),
        # PKTTBL Data
        ByteField("PktTblLastLoadStatus", 0),
        ByteField("SpareAlignByte", 0),
        LEShortField("PktTblAttrErrCnt", 0),
        # PKTMGR Data
        LEShortField("TlmSockId", 0),
        StrFixedLenField("TlmDestIp", b"", 16),
    ]


bind_layers(CCSDSPacket, KIT_TO_HkTlmPkt, pkttype=0, apid=0x080)


class CFE_ES_ShellTlmPkt(Packet):
    """cFE Event Service Shell TLM Packet"""
    name = "CFE_ES_ShellTlmPkt"
    fields_desc = [
        StrFixedLenField("ShellOutput", b"", 64),  # CFE_MISSION_ES_MAX_SHELL_PKT = 64
    ]


bind_layers(CCSDSPacket, CFE_ES_ShellTlmPkt, pkttype=0, apid=0x00f)


class KIT_CI_HkTlmPkt(Packet):
    """KIT Command Ingest Housekeeping TLM Packet"""
    name = "KIT_CI_HkTlmPkt"
    fields_desc = [
        # CMDMGR Data
        LEShortField("ValidCmdCnt", 0),
        LEShortField("InvalidCmdCnt", 0),
        # UPLINK Data
        ByteField("SocketConnected", 0),
        ByteField("MsgTunnelEnabled", 0),
        LEShortField("SocketId", 0),
        XLEIntField("RecvMsgCnt", 0),
        XLEIntField("RecvMsgErrCnt", 0),
        LEShortField("MappingsPerformed", 0),
        # UPLINK_LastMapping LastMapping
        LEShortField("LastMapping_Index", 0),
        LEShortField("LastMapping_OrgMsgId", 0),
        LEShortField("LastMapping_NewMsgId", 0),
    ]


bind_layers(CCSDSPacket, KIT_CI_HkTlmPkt, pkttype=0, apid=0x084)


class KIT_SCH_HkTlmPkt(Packet):
    """KIT Scheduler Housekeeping TLM Packet"""
    name = "KIT_SCH_HkTlmPkt"
    fields_desc = [
        # CMDMGR Data
        LEShortField("ValidCmdCnt", 0),
        LEShortField("InvalidCmdCnt", 0),
        # TBLMGR Data
        ByteField("MsgTblLastLoadStatus", 0),
        ByteField("SchTblLastLoadStatus", 0),
        LEShortField("MsgTblAttrErrCnt", 0),
        LEShortField("SchTblAttrErrCnt", 0),
        # SCHTBL
        LEIntField("SlotsProcessedCount", 0),
        LEIntField("ScheduleActivitySuccessCount", 0),
        LEIntField("ScheduleActivityFailureCount", 0),
        LEIntField("ValidMajorFrameCount", 0),
        LEIntField("MissedMajorFrameCount", 0),
        LEIntField("UnexpectedMajorFrameCount", 0),
        LEIntField("TablePassCount", 0),
        LEIntField("ConsecutiveNoisyFrameCounter", 0),
        LEShortField("SkippedSlotsCount", 0),
        LEShortField("MultipleSlotsCount", 0),
        LEShortField("SameSlotCount", 0),
        LEShortField("SyncAttemptsLeft", 0),
        LEShortField("LastSyncMETSlot", 0),
        ByteField("IgnoreMajorFrame", 0),
        ByteField("UnexpectedMajorFrame", 0),
    ]


bind_layers(CCSDSPacket, KIT_SCH_HkTlmPkt, pkttype=0, apid=0x099)


class CFE_ES_ShellCmdPkt(Packet):
    """cFE Executive Service Shell Command: CFE_ES_CMD_MID = 0x1806, CFE_ES_SHELL_CC = 3"""
    name = "CFE_ES_ShellCmdPkt"
    fields_desc = [
        StrFixedLenField("CmdString", b"", 64),  # CFE_MISSION_ES_MAX_SHELL_CMD = 64
        StrFixedLenField("OutputFilename", b"", 64),  # CFE_MISSION_MAX_PATH_LEN = 64
    ]


bind_layers(CCSDSPacket, CFE_ES_ShellCmdPkt, pkttype=1, apid=0x006, cmd_func_code=3)


class CFE_ES_QueryAllCmdPkt(Packet):
    """cFE Executive Query All Command: CFE_ES_CMD_MID = 0x1806, CFE_ES_QUERY_ALL_CC = 9"""
    name = "CFE_ES_QueryAllCmdPkt"
    fields_desc = [
        StrFixedLenField("FileName", b"", 64),  # CFE_MISSION_MAX_PATH_LEN = 64
    ]


bind_layers(CCSDSPacket, CFE_ES_QueryAllCmdPkt, pkttype=1, apid=0x006, cmd_func_code=9)


class CFE_ES_QueryAllTasksPkt(Packet):
    """cFE Executive Query All Tasks Command: CFE_ES_CMD_MID = 0x1806, CFE_ES_QUERY_ALL_TASKS_CC = 24"""
    name = "CFE_ES_QueryAllTasksPkt"
    fields_desc = [
        StrFixedLenField("FileName", b"", 64),  # CFE_MISSION_MAX_PATH_LEN = 64
    ]


bind_layers(CCSDSPacket, CFE_ES_QueryAllTasksPkt, pkttype=1, apid=0x006, cmd_func_code=24)


def build_kit_to_enable_telemetry():
    """
    Send a KIT_TO ENABLE_TELEMETRY command

    Dump from COSMOS:

        00000000: 18 80 C0 00 00 11 07 9A 31 32 37 2E 30 2E 30 2E
        00000010: 31 00 00 00 00 00 00 00
    """
    # The payload is the local IP address where telemetry data is sent
    # Func code 7 = KIT_TO_ENABLE_OUTPUT_CMD_FC
    pkt = CCSDSPacket(apid=0x80, cmd_func_code=7) / b'127.0.0.1\x00\x00\x00\x00\x00\x00\x00'
    payload = bytes(pkt)
    assert payload.hex() == '1880c0000011079a3132372e302e302e3100000000000000', "Sanity check failed"
    return payload


class Codec(Sink):
    def __init__(self, show_hk=False):
        super().__init__()
        self.show_hk = show_hk
        self._buf = b""

    def push(self, msg: bytes):
        self._buf += msg
        while True:
            pkt = CCSDSPacket(self._buf)
            pkt_size = pkt.pkt_length + 7
            if pkt_size > len(self._buf):
                return
            pkt = CCSDSPacket(self._buf[:pkt_size])
            self._buf = self._buf[pkt_size:]

            # Show packet only if some fields changed from the reference
            if pkt.version != 0 or pkt.pkttype != 0 or pkt.has_sec_header != 1 or pkt.segm_flags != 3:
                pkt.show()
                continue

            apid_name = pkt.fieldtype['apid'].i2repr(pkt, pkt.apid)
            # Change to a less-visible color when showing Housekeeping messages
            is_hk = apid_name.endswith('_HK_TLM')
            if is_hk and not self.show_hk:
                # Do not show housekeeping telemetry messages
                continue

            print("{}[< {}={:#x}] [seq={:#x}] {}{}".format(
                "\033[34m" if is_hk else "",
                apid_name,
                pkt.apid,
                pkt.seq_count,
                repr(pkt.payload),
                "\033[m" if is_hk else "",))

            # self._high_send(pkt)

    def high_push(self, msg: Packet):
        fin_pkt = binascii.unhexlify("deadbeef") + bytes(msg)
        self._send(fin_pkt)
        #self._send(bytes(msg))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--scapy-pipes', action='store_true')
    parser.add_argument('-H', '--show-hk', action='store_true')
    args = parser.parse_args()

    # cfs-wrapper wraps UDP:1234 from cFS to TCP:54321
    client = TCPConnectPipe(name="client", addr='127.0.0.1', port=54321)
    display = ConsoleSink(name="display")
    codec = Codec(show_hk=args.show_hk)
    client > codec
    codec > client
    codec >> display
    pt = PipeEngine(codec)
    # pt.graph(type="png", target="> scapy-pipes.png")
    pt.start()

    def send_noops(fast=False):
        """Send many NOOP commands (function code 0)

        Usually these commands display build versions in the event log"""
        for apid_val, apid_name in sorted(APID_NAMES[1].items()):
            if apid_name.endswith('_CMD'):
                if not fast:
                    print("Sending NOOP_CC on {}={:#05x}".format(apid_name, apid_val))
                codec.high_push(CCSDSPacket(pkttype=1, apid=apid_val, cmd_func_code=0))
                if not fast:
                    time.sleep(1)

    def sh(cmd, filename=b'/cf/cmd.tmp'):
        """Send a CFE_ES_SHELL_CC command"""
        if not isinstance(cmd, bytes):
            cmd = cmd.encode()
        if not isinstance(filename, bytes):
            filename = filename.encode()
        pkt = CCSDSPacket() / CFE_ES_ShellCmdPkt(CmdString=cmd, OutputFilename=filename)
        codec.high_push(pkt)

    time.sleep(0.5)
    codec.high_push(build_kit_to_enable_telemetry())
    time.sleep(1)
    # codec.high_push(CCSDSPacket(apid=0x82))  # Get flag
    send_noops(fast=True)
    sh('id -nu')
    IPython.embed()
