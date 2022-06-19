# HACK-A-SAT 3: Stars Above

* **Category**: Rocinante Strikes Back
* **Points:** 371
* **Solves:** 2
* **Description:**

> Starlunk has been nothing but trouble since I subscribed. Those hackers really did a number on things.
>
> Maybe we can force the system to route our traffic better. Work smarter not harder right?

## Write-up

_Write-up by Solar Wine team_

The challenge provides a remote service which expects hexadecimal input:

- (the server sent) `Successfully connected to 'space'`
- (we sent) `?`
- (the server sent) `Encountered Non-Hex string, dropping...`
- (we sent) `00`
- (the server sent) `Couldn't decode message from hex...`

We are also provided with a Rust binary compiled for x86-64.
This program connects to some server provided through the environment variable `SERVER` (`localhost:31337` by default) and exchanges messages using a function named `client::comms::CommManager::start_communication`.

It receives messages encoded in hexadecimal which are deserialized using the Bincode format specified on <https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md>.

The received message is decoded in a structure named `Message`.
A possible way to obtain the fields of `Message` consists in reverse-engineering the functions which displays the content of a `Message` instance:

```c++
void <messages::messages::Message_as_core::fmt::Debug>::fmt(long param_1,undefined8 param_2)
{
  long local_30;
  undefined local_28 [16];
  
  local_28 = core::fmt::Formatter::debug_struct(param_2,"Message",7);
  local_30 = param_1;
  core::fmt::builders::DebugStruct::field
            (local_28,"route",5,&local_30,&PTR_drop_in_place<&messages_route_Route>_00166e68);
  local_30 = param_1 + 0x20;
  core::fmt::builders::DebugStruct::field
            (local_28,"body",4,&local_30,&PTR_drop_in_place<&messages_messages_MessageBody>_00166e88
            );
  core::fmt::builders::DebugStruct::finish(local_28);
  return;
}
```

This function calls two functions to decode a field named `route` of type `messages::route::Route` and a field named `body` of type `messages::messages::MessageBody`.
Repeating this step leads to decoding the following Rust structure:

```rust
struct Message {
    route: struct Route {
        src: u16,
        dst: Vec<u16>,
    }
    body: enum MessageBody {
        Hello: u16, // bincode tag 0
        NetworkCheckReq: u16, // bincode tag 1
        NetworkCheckAck: u16, // bincode tag 2
        SendFlag, // bincode tag 3
        Flag: String, // bincode tag 4
        DetourReq: (u16, u16), // bincode tag 5
    }
}
```

When running the program with `./challenge', "5", "32"`, it displays

```text
Sending message Message { route: Route { src: 1, dst: [0] }, body: Hello(1) }
```

and sends 18 bytes to a server at `localhost:31337`.
These bytes can be decoded (using Bincode format) in the following way:

```text
0100                                 - src: u16 = 1
    0100000000000000                 - dst.len: u64 = 1
                    0000             - dst[0]: u16 = 0
                        00000000     - body.tag = 0 (Hello)
                                0100 - u16: 1
```

When we changed some hexadecimal bytes and wrote them on the remote server provided by the challenge, it displayed:

```text
010001000000000000000000000000000200
Sending message Message { route: Route { src: 1, dst: [0] }, body: Hello(2) }

01000100000000000000000003000000
Sending message Message { route: Route { src: 1, dst: [0] }, body: SendFlag }
```

So we managed to send a command requesting to send the flag... but did not get any reply

Also, when changing the destination, we found out that most messages triggered a warning `Message dropped by 'physics'...`, except when sending a message to destination 12:

```text
(sending) 010001000000000000000c00010000000500
Message { route: Route { src: 99, dst: [99] }, body: NetworkCheckAck(99) }
Sending message Message { route: Route { src: 1, dst: [12] }, body: NetworkCheckReq(5) }
Message { route: Route { src: 30, dst: [5] }, body: NetworkCheckAck(12) }
```

We got a message from source 30 to destination 5.

At some point in reverse-engineering the Rust program, we stumbled upon a function named `routelib::get_route` which crafts the destination vector of a message being sent.
It uses a table at address `0x55340`, holding 17 entries of 6 integers:

```text
ID   Type   Neighbours
 0     2     0     0     0     0
 1     0    12     2     0    20
 2     0     1     3     0    20
 3     0     2     4     0    20
 4     0     3     5     0    30
 5     0     4     6     0    30
 6     0     5     7     0    30
 7     0     6     8     0    40
 8     0     7     9     0    40
 9     0     8    10     0    40
10     0     9    11     0    50
11     0    10    12     0    50
12     0    11     1     0    50
20     1     1     2     3     0
30     1     4     5     6     0
40     1     7     8     9     0
50     1    10    11    12     0
```

Here is a high-level description of what `routelib::get_route` does:

- There are 17 satellites: 0, 1, 2..., 12 and 20, 30, 40, 50.
- Satellites 1 to 12 are in a ring: each one can directly communicates with its neighbours.
- Satellites 20 to 50 are the gateways which can be each be used to reach 3 satellites:

  - 20 is connected to 1, 2, 3
  - 30 is connected to 4, 5, 6
  - 40 is connected to 7, 8, 9
  - 50 is connected to 10, 11, 12

- Satellite 0 connects together satellites 20 to 50.

For example, when satellite 5 wants to send a message to satellite 8, it crafts a route which goes through 30, 0, 40 and 8.
It results in a message with `dst = [30, 0, 40, 8]`, received by 30.
This satellite then forwards the message with `dst = [0, 40, 8]` to 0, which continues forwarding the message until 8 receives the message.

When sending the `SendFlag` message to satellite 5 (using `000002000000000000001e00050003000000`), the service displays:

```text
Sending message Message { route: Route { src: 0, dst: [30, 5] }, body: SendFlag }
Sat_5: Starting Network Check...
Message { route: Route { src: 30, dst: [5] }, body: SendFlag }
Sat_5: Network Check Succeeded! Sending Flag to 8...
```

The satellite sends the flags to 8, and we are interested in the content of this message.
How can we make the remote server also decode the message?

The program luckily includes a *Detour* feature which enables modifying the route that messages take.
For example, if satellite 40 is configured with a detour `(8, 7)`, when it receives a message for 8, it will forward it to 7 instead.
Such a detour can be set up by sending a `DetourReq` message.

Here is a program which sends `DetourReq` message so that when satellite 40 receives a message for 8, this message is forwarded to 7, 6, 5, 4, 3, 2, 1, 12, 11, 10, 9 and 8.

```python
import struct
from pwn import *

conn = remote("starsabove.satellitesabove.me", 5500)
line = conn.recvline()
assert line == b'Ticket please:\n', line
conn.sendline(
    b"ticket{lima322514xray3:GI8QCBCzjEwB3trVn6APiFUzoPDBt0GAaR_Qy9N5GN6JOfERY8HAH2HBN7Xa0jR81Q}")

line = conn.recvline()
print(f"[{datetime.datetime.now().strftime('%H:%M:%S')} CLIENT] {line!r}")
assert line == b"Successfully connected to 'space'\n", line

def send_msg(src, dst, msgtype, param):
    msg = struct.pack('<HQ', src, len(dst))
    for d in dst:
        msg += struct.pack('<H', d)
    msg += struct.pack('<I', msgtype) + param
    print(f"[CLIENT] ({src},{dst},{msgtype}:{param.hex()}) > {pkt.hex()}")
    conn.sendline(pkt.hex().encode("ascii"))

def send_hello(src, dst, number):
    send_msg(src, dst, 0, struct.pack("<H", number))

def send_net_check_req(src, dst, number):
    send_msg(src, dst, 1, struct.pack("<H", number))

def send_sendflag(src, dst):
    send_msg(src, dst, 3, b'')

def send_detourreq(src, dst, number1, number2):
    send_msg(src, dst, 5, struct.pack("<HH", number1, number2))

# Send messages from satellite 5 to retoute packets targeting 8
send_detourreq(5, [30, 0, 40], 8, 7)
send_detourreq(5, [30, 0, 40, 7], 8, 6)
send_detourreq(5, [6], 8, 5)
send_detourreq(5, [30, 5], 8, 4)
send_detourreq(5, [4], 8, 3)
send_detourreq(5, [30, 0, 20, 3], 8, 2)
send_detourreq(5, [30, 0, 20, 2], 8, 1)
send_detourreq(5, [30, 0, 20, 1], 8, 12)
send_detourreq(5, [30, 0, 50, 12], 8, 11)
send_detourreq(5, [30, 0, 50, 11], 8, 10)
send_detourreq(5, [30, 0, 50, 10], 8, 9)

send_sendflag(5, [30, 0, 20, 2])
```

When sending the `SendFlag` request, the following log appears:

```text
Sending message Message { route: Route { src: 5, dst: [30, 0, 20, 2] }, body: SendFlag }
Sat_2: Starting Network Check...
Message { route: Route { src: 30, dst: [5] }, body: NetworkCheckReq(2) }
Sat_2: Network Check Failed! Goodbye...
Message { route: Route { src: 6, dst: [5, 8] }, body: NetworkCheckReq(2) }
Sat_2: Network Check Succeeded! Sending Flag to 8...
Message { route: Route { src: 6, dst: [5, 8] }, body: Flag("flag{lima322514xray3:GDa5BepzVbgOQPIVwGqm3E3oPh8ujJLiYjYckvLkmjJxHx4PoFfLUPyC_wvOXtXYk6gwPWRcsET8VDfvrmevRKY}") }
```
