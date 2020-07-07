# SPACE SECURITY CHALLENGE 2020 HACK-A-SAT: Can you hear me now

* **Category:** Ground Segment
* **Points:** 59 (at the end of the challenge, >300 at the time we solved it iirc)
* **Solves:** 75
* **Description:**

> LaunchDotCom's ground station is streaming telemetry data from its Carnac 1.0 satellite on a TCP port. Implement a decoder from the XTCE definition.
>
> Connect to the challenge on hearmenow.satellitesabove.me:5032 . Using netcat, you might run nc hearmenow.satellitesabove.me 5032
>
> You'll need these files to solve the challenge.
>
>    https://static.2020.hackasat.com/6cb8b764695c0776577be7ed6ce09759fc4115f8/telemetry.zip


## Write-up

_Write-up by Solar Wine team_

## Challenge service

The challenge service on `hearmenow.satellitesabove.me:5032` asks for the team ticket upon connection, then yields the address of the telemetry service:

```shell
$ nc hearmenow.satellitesabove.me 5032
Ticket please:
ticket{zulu66287alpha:GC9heYgErLjOxsTj0rKZzBmRC(...)ew}
Telemetry Service running at 18.219.199.203:25647
```

The Telemetry Service sends a series of messages, the last one of which is 101 bytes long. No obvious flag there...

## Provided documentation


The provided `telemetry.zip` archive contains a single file, `telemetry.xtce`.

Googling XTCE leads to the documentation of the XML Telemetric and Command
Exchange format, with a 32-page specification, which describes message formats.

In the provided `telemetry.xtce` file, the following lines seem very interesting:

```xml
    <!-- Parameters used by FLAG Gen  -->
    <xtce:Parameter parameterTypeRef="7BitInteger" name="FLAG11"/>
    ...
    <xtce:Parameter parameterTypeRef="7BitInteger" name="FLAG120"/>
```

Apparently, flag characters are transmitted as 7 bits integer. This is a challenge, who has time to understand a 32-page specification and a 33KB XML file?

We don't know what the first bit of the first flag character is, so let's bruteforce them :

```python
# a is the hex value of the longest message received from the Telemetry Service
a=int('0x0066e587005ecdb30e7f7ebaecead9b3270df0ece1a30ba8f07'
      '0b8e1de271c78e2f45b6ba72afbfcb2d1d58d77162555ebb34e4a'
      'bcefd768df5b2cd625adb4d7ce88b8b637d5a25d8e56bcb1ed3b8'
      '38f32293473debb5c523a70995597ae97e0b298d3bfd0', 16)

for i in range(8):
    b = a >> i
    res = ''
    while b:
        res += chr(b&0x7F)
        b >>= 7
        if b ==0:
            break
    print(res)
```

This script fills up my terminal with garbage... And what looks like a reversed flag.
Replacing the last line with `print(''.join(reversed(res)))` does the job, a flag appears :)

This was done soon after the release of the challenge, so the reward was high!

## Solution script

The process we followed during the challenge involved manually passing bits of
information between hastily written scripts. The following script, written
after the competition for the purpose of this write-up, autonomously obtains
connects to the service and displays the flag.

```python
#!/usr/bin/env python3

from scapy.all import *
import struct
import re
import datetime
# python3 -m pip install --upgrade pwntools
from pwn import *


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

        if self.getfieldval("CCSDS_PLENGTH") is None:
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


if __name__ == "__main__":
    log.info(f"Current time is {datetime.datetime.now().isoformat()}")
    TICKET = ("ticket{zulu66287alpha:GC9heYgErLjOxsTj0rKZzBmR"
              "CgFo492xFDX_FbdiIGR6ZSo5KZl0HXzYF9D4sn4eew}")
    conn = remote("hearmenow.satellitesabove.me",5032)
    l = conn.recvline()
    with log.progress("Sending ticket") as lp:
        conn.sendline(TICKET)
        lp.success()
    l = conn.recvline()
    log.info(l.decode())
    m = re.match(b"Telemetry Service running at (\S+):(\S+)", l)
    conn.close()
    host, port = m.groups()

    conn = remote(host, int(port))
    with log.progress("Waiting for the flag") as lp:
        while True:
            raw = conn.recv()
            p = TMPacketHeader(raw)
            if p.haslayer(FlagData):
                lp.success(f"flag value is: {p['FlagPacket'].flagvalue()}")
                break
```

This script has the following output:

```shell
[*] Current time is 2020-06-07T13:12:58.896471
[+] Opening connection to hearmenow.satellitesabove.me on port 5032: Done
[+] Sending ticket: Done
[*] Telemetry Service running at 18.219.199.203:23244
[*] Closed connection to hearmenow.satellitesabove.me port 5032
[+] Opening connection to b'18.219.199.203' on port 23244: Done
[+] Waiting for the flag: flag value is: flag{zulu66287alpha:GEVYr(...)Tnig}
```
