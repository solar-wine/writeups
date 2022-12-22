# HACK-A-SAT 3: Digital Twin exploration and tooling

* **Category:** Preparation
* **Points:** N/A
* **Description:**

We received on October 14th a private SSH key and a PowerPoint presentation
explaining how to connect to our team DigitalTwin.
We had access to these services:

* COSMOS5 Web interface: <https://cosmos.solarwine-digitaltwin.satellitesabove.me>
* CESIUM visualization: <https://cesium.solarwine-digitaltwin.satellitesabove.me>
* Grafana dashboard: <https://dashboard.solarwine-digitaltwin.satellitesabove.me>
* Web terminal: <https://terminal.solarwine-digitaltwin.satellitesabove.me>

The Grafana dashboard plotting simulation information from
[Basilisk](http://hanspeterschaub.info/basilisk/) was not available on the real satellite.

The Digital Twin satellite is positioned on a geostationary orbit, which means
we have persistent communication to prototype tools.

## Exploration

### Networking exploration

All the given services are hosted behind the same IPv4 from Amazon AWS.

The Web terminal does not allow `ping`, but using `getent hosts` and some IPv4
address guessing we leaked the following addresses:

```text
172.18.0.1 ip-172-18-0-1.ec2.internal
172.18.0.2 production-test (our Web terminal machine)
172.18.0.3 digitaltwin-traefik-1.digitaltwin_external
172.18.0.4 digitaltwin-dashboard-1.digitaltwin_external (grafana on port 3000)
```

We are able to send requests to COSMOS Web API using cURL on the reverse proxy
(`172.18.0.3`), this could be useful later for scripting.

### Digital Twin setup

We connect to COSMOS, and run `GS > procedures > gs_script.rb` which:

1. selects the Kathmandu Ground Station,
2. configure its radio,
3. steers its antenna toward the simulated satellite,
4. and sends `KIT_TO ENABLE_TELEMETRY` command.

After running this script, we see telemetry packets counters rising
in COSMOS.

*We didn't try to implement the azimuth and elevation computation before
the final.*

### Leaking COSMOS custom RubyGems

By comparing the DigitalTwin COSMOS to [a local COSMOS instance](https://github.com/BallAerospace/COSMOS/blob/master/cosmos-control.sh),
we spotted two extra gems:

* `cosmos-has3-gnd-1.0.0.gem__20221015173854`
* `cosmos-has3-sat-1.0.1.gem__20221015173851`

COSMOS enables users to upload new Gems or to remove installed Gems, but
does not allow to download them via a button (*strange user-experience*).
We analyzed its source code and the configuration of its storage service, MinIO.
There is a MinIO login interface on <https://cosmos.solarwine-digitaltwin.satellitesabove.me/minio/login>, but we did not have the credentials for it.
We found a proxy that enabled us to dump any file from its known path, using the COSMOS password instead:

```bash
curl -H 'Authorization: REDACTED' 'https://cosmos.solarwine-digitaltwin.satellitesabove.me/cosmos-api/storage/download/cosmos-has3-gnd-1.0.0.gem?scope=DEFAULT&bucket=gems' | jq
{
  "url": "/files/gems/cosmos-has3-gnd-1.0.0.gem?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=cosmosminio%2F20221022%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20221022T120426Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=4be2862fba5e05fdf2bc8f1a6486f877b99de68546ee99b29aed0a8f61873eb9",
  "headers": {},
  "method": "get"
}
```

The returned `url` worked, and we dumped all the gems, including
`cosmos-has3-gnd-1.0.0.gem` and `cosmos-has3-sat-1.0.1.gem`.

We wrote our own `cosmos-has3-*.gemspec` and `Rakefile` and made sure we were
able to patch, rebuild and upload these Gems to COSMOS.

![Hack-a-Sat1 nostalgia](images/mmso.jpg)

Using this technique, we added `mm.so` definitions (from OpenSatKit) to our DigitalTwin COSMOS
although it turned out useless as `mm.so` had been removed on the final satellite.
During the final, we used this technique to compare the changes made to COSMOS
and observe this magnificent warning:
```latex
$`\textcolor{red}{\text{THIS BRANCH CONTAINS CHALLENGE CONTENT. DO NOT LEAK TO TEAM DIGITALTWIN.}}`$
```

We were able to fix the `SET_Q_TRACKING_GAIN` command length,
change the max length of debug pointer in `MON RESET_CTRS` command and
add missing `TELESCOPE RAW_EXPOSURE_TLM_PKT`, `TELESCOPE STORE_MISSION_DATA`
and `TELESCOPE BULK_MISSIONS` definitions.

## Tooling

### Telemetry monitoring

We created a Prometheus exporter to collect incoming telemetry in a timeseries
database.
We used the WebSocket endpoint `/cosmos-api/cable` to subscribe to telemetry events.
The COSMOS handbook enumerated all the possible packets with their fields.
Each field can be mapped to a WebSocket event by adding some underscores and using a type among `CONVERTED`, `RAW` or `FORMATTED`.
For example, the EPS battery charge rate can be received by subscribing to `TLM__EPS__BATTERY__NET__CONVERTED`, which is field `NET` of packet `BATTERY` in target `EPS`.

We made a Grafana dashboard with alerts to be notified before the safe
mode triggers.

![Grafana dashboard](images/grafana.png)

### Logging cFE and Ground Station events

Using the same principles as the telemetry monitoring, we made a script that
subscribes to `CFE_EVS EVENT_MSG_PKT` and `GS ACCESS_STATUS` telemetry
and then forwards these in a Discord channel.

![Satellite and Ground Station journal](images/sat_logs.png)

### Satellite emulation

At the time of the competition, the latest stable release of QEMU, version 7.1, was unable to emulate cFS `core-cpu1`.
It fails with:

```text
CFE_PSP: Default Reset Type = PO
CFE_PSP: Default Reset SubType = 1
CFE_PSP: Default CPU ID = 1
CFE_PSP: Default Spacecraft ID = 42
CFE_PSP: Default CPU Name: cpu1
CFE_PSP: Starting the cFE with a POWER ON reset.
Error: pthread_mutex_init failed: Operation not supported
OS_API_Impl_Init(0x1) failed to initialize: -1
CFE_PSP: OS_API_Init() failure
```

Looking at the syscalls which were done, we found that we need a version of QEMU [that implements PI futexes](https://gitlab.com/qemu/qemu/commit/c72a90df47b990572ac4fdb7e918005466446db9).
Indeed, this feature was merged in `master` branch but was not part of a release yet.
We choose to use current `master` (commit hash `214a8da23651f2472b296b3293e619fd58d9e212`).

```bash
git clone https://gitlab.com/qemu/qemu.git
git -C qemu checkout 214a8da23651f2472b296b3293e619fd58d9e212
(cd qemu && ./configure --target-list=riscv32-linux-user && make -j4)

# Run core-cpu1
LIB_DIR="path/to/remote_sat/lib"
qemu/build/qemu-riscv32 -L "$LIB_DIR" -E "LD_LIBRARY_PATH=$LIB_DIR" "$LIB_DIR/ld-linux-riscv32-ilp32d.so.1" ./core-cpu1
```

Some applications cannot work properly, as this satellite does not have any sensor or actuator, but the telemetry works!
This virtual satellite can accept CCSDS packets sent to UDP 127.0.0.1:1234 (they are received by `KIT_CI` module) and after sending a `KIT_TO ENABLE_TELEMETRY` packet, the satellite sends its telemetry packets to UDP 127.0.0.1:1235.
We used [our Scapy implementation of the CCSDS packets from two years ago](https://github.com/solar-wine/tools-for-hack-a-sat-2020/tree/master/scapy-space-packets) to craft the packets.

In the previous Hack-a-Sat editions, this Scapy implementation talked to the satellite through COSMOS.
To communicate with the UDP ports directly, we needed to slightly modify the configuration of Scapy Pipes which were used:

```python
from scapy.all import *

client = UDPClientPipe(name="client", addr="127.0.0.1", port=1234)
telemetry_server = UDPServerPipe(name="telemetry", addr="127.0.0.1", port=1235)

codec = Codec(recv_sync=True, add_send_sync=False)
display = ConsoleSink(name="display")
telemetry_server > codec
codec > client
pt = PipeEngine(codec)
pt.start()
```

The `Codec` class handles the serialization of packets sent to the virtual satellite (function `high_push`) and the parsing of received packets received, which also include a 4-byte synchronization pattern.

```python
# Synchronisation pattern for UART_TO_CI
UART_SYNC_PATTERN = b'\xde\xad\xbe\xef'


class Codec(Sink):
    def __init__(self, recv_sync=False, add_send_sync=False):
        super().__init__()
        self.recv_sync = recv_sync
        self.add_send_sync = add_send_sync
        self._buf = b""

    def push(self, msg: bytes):
        self._buf += msg
        # print(f"\033[35mReceiving {len(msg)}/{len(self._buf)} bytes: {msg[:42].hex()}\033[m")
        while True:
            if self.recv_sync:
                if len(self._buf) < 10:
                    return
                if not self._buf.startswith(UART_SYNC_PATTERN):
                    # Drop bytes until the synchronisation pattern appears
                    try:
                        drop_bytes = self._buf.index(UART_SYNC_PATTERN)
                    except ValueError:
                        drop_bytes = len(self._buf)
                    assert drop_bytes != 0
                    print(f"[<] Dropping {drop_bytes} bytes: {self._buf[:drop_bytes].hex()}")
                    self._buf = self._buf[drop_bytes:]
                    continue

                current_ccsds_buffer = self._buf[4:]
            else:
                current_ccsds_buffer = self._buf

            pkt = CCSDSPacket(current_ccsds_buffer)
            pkt_size = pkt.pkt_length + 7
            if pkt_size > len(current_ccsds_buffer):
                return
            pkt = CCSDSPacket(current_ccsds_buffer[:pkt_size])
            self._buf = current_ccsds_buffer[pkt_size:]

            # Show packet only if some fields changed from the reference
            if pkt.version != 0 or pkt.pkttype != 0 or pkt.has_sec_header not in {0, 1} or pkt.segm_flags != 3:
                print("UNEXPECTED HEADER FIELDS in received CCSDS packet:")
                pkt.show()

            try:
                show_ccsds_packet(pkt, prefix="<")
            except Exception as exc:
                print(f"ERROR: Exception while showing a packet: {exc!r}")
                raise
            self._high_send(pkt)

    def high_push(self, msg: Packet):
        msg_bytes = bytes(msg)
        if self.add_send_sync:
            # Add 4 bytes of synchronisation
            msg_bytes = UART_SYNC_PATTERN + msg_bytes
        self._send(msg_bytes)
```

Using this Python code and some classes similar to the content of <https://github.com/solar-wine/tools-for-hack-a-sat-2020/tree/master/scapy-space-packets>, we can send commands.

```python
# Enable telemetry
codec.high_push(CCSDSPacket() /
    KIT_TO_ENABLE_TELEMETRY_CmdPkt(IP_ADDR='127.0.0.1'))

# List the applications
codec.high_push(CCSDSPacket() /
    CFE_ES_SHELL_CmdPkt(CMD_STRING="ES_ListApps", OUTPUT_FILENAME="/cf/cmd"))

# Run a shell command
codec.high_push(CCSDSPacket() /
    CFE_ES_SHELL_CmdPkt(CMD_STRING="uname -a", OUTPUT_FILENAME="/cf/cmd"))

# Start MM application
codec.high_push(CCSDSPacket() / CFE_ES_START_APP_CmdPkt(
    APP_NAME="MM",
    APP_ENTRY_POINT="MM_AppMain",
    APP_FILENAME="/cf/mm.so",
    STACK_SIZE=16384,
    PRIORITY=90,
))
```

This environment was useful to debug issues in the challenges related to the Flight Software.
