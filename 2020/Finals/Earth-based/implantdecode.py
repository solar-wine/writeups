#!/usr/bin/env python3
import IPython  # noqa

from scapy.all import *

from all_packets import *


UART_SYNC_PATTERN = b'\xde\xad\xbe\xef'

pcap = rdpcap('implant_capture.pcap')

for pktidx, pkt in enumerate(pcap):
    try:
        if pkt.haslayer(DNS):
            continue
        deadbeefidx = bytes(pkt).index(UART_SYNC_PATTERN) + 4
        ccs = CCSDSPacket(bytes(pkt)[deadbeefidx:])
        ccs.show()
    except ValueError:
        print(f"no deadbeef in pkt #{pktidx}, skipping (payload={pkt[Raw]})")

# IPython.embed()
