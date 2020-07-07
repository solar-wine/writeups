# SPACE SECURITY CHALLENGE 2020 HACK-A-SAT: Sun? On my Sat?

* **Category:** Satellite  Bus
* **Points:** 324
* **Solves:** 4 
* **Description:** 

		
> "We've uncovered a strange device listening on a port I've connected you to 
> on our satellite. At one point one of our engineers captured the firmware 
> from it but says he saw it get patched recently. We've tried to communicate 
> with it a couple times, and seems to expect a hex-encoded string of bytes, 
> but all it has ever sent back is complaints about cookies, or something. See 
> if you can pull any valuable information from the device and the cookies we 
> bought to bribe the device are yours! "

## Introduction

_Write-up by Solar Wine team_

Along with the description there is the following binary:

```
$ file sparc1-papa84686zulu/test.elf
sparc1-papa84686zulu/test.elf: ELF 32-bit MSB executable, SPARC, 
version 1 (SYSV), statically linked, not stripped
```

Two important information: 

* the binary is not stripped, so we have every debug information \\o/
* it's a **SPARC** binary, an ISA none of us ever reversed previously

In order to reverse it statically, you can use Ghidra (thanks again, NSA!) or if you're a die-hard IDA user like myself, use [Cisco Talos's wonderful GhIDA plugin](
https://github.com/Cisco-Talos/GhIDA)  which brings Ghidra's decompiler to IDA. It's not the most ideal setup, but I didn't have time to learn Ghidra's idiosyncrasies.

The binary is a traditional message processing server accepting hexadecimal strings as input on stdin and has the following message pump:

```c
	int msgHandler(uint8_t* buffer, int buffer_len)
	{
	  bool b_has_sent_header;
	  int message_len;
	  uint message_type;
	  int current_message;

	  if (0 < buffer_len) {
	    b_has_sent_header = false;

	    do {

	      while( true ) {

	        current_message = buffer;
	        message_len = getCmdLen(current_message);
	        message_type = getCmdType(current_message);

	        if ((!b_has_sent_header) && (message_type != 0)) {
	          hangup("Missing Header");
	        }

	        if (message_type != 1) {
	          break;
	        }

	        // CMD 0x01 : GET_INFO
	        str *info = handleGetInfo(current_message);
	        buffer_len = buffer_len - message_len;
	        puts(info);
	        
	        buffer = current_message + message_len;
	        if (buffer_len < 1) {
	          goto ON_EXIT;
	        }
	      }

	      // CMD 0x00 : NEGOCIATE_HEADER
	      if (message_type < 2) {
	        b_has_sent_header = true;
	        handleHeader(current_message);
	        buffer_len = buffer_len - message_len;
	      }

	      else {

	        // CMD 0x02 : SHUTDOWN
	        if (message_type == 2) {
	          hangup("Shutdown Requested");
	          buffer_len = buffer_len - message_len;
	        }
	        else {

	          // CMD 0x03 : GET_TROLLED
	          if (message_type == 3) {
	            getFlag(current_message);
	            buffer_len = buffer_len - message_len;
	          }
	          else {

	            // CMD 0x04-0xFF : GET_OUT
	            hangup("Unexpected Message Section");
	            buffer_len = buffer_len - message_len;
	          }
	        }
	      }
	      buffer = current_message + message_len;
	    } while (0 < buffer_len);
	    
	ON_EXIT:
	    buffer = current_message + message_len;
	  }

	  puts(DWORD_ARRAY_4001af78);
	  return buffer;
	}
```


There are four "commands" available:

* 0x00 : **NEGOCIATE_HEADER** 
* 0x01 : **GET_INFO** 
* 0x02 : **SHUTDOWN** 
* 0x03 : **GET_FLAG**  

Ideally you want to be able to execute the ``GET_FLAG`` path. However we can't call it right away since there is a boolean ``b_has_sent_header`` which force every client to send a ``NEGOCIATE_HEADER`` command before processing any other commands.


## Message parsing and negotiating header


As most applicative server, this binary has custom message parsing routines that we need to reverse in order to forge "correct" command packets. Here is a diagram explaining how they are created:

\begin{samepage}
\begin{minted}[fontsize=\footnotesize]{text}
0      1                          n
+------+--------------------------+
|      |                          |
| msg  |                          |
|      |        Messages          |
| len  |                          |
|      |                          |
+------+----+---------------------+
            |
            |  0     1      2                  n
            |  +-----+------+------------------+
            |  |     |      |                  |
            |  | cmd | cmd  |                  |
            +->+     |      |   cmd payload    |
               | len | type |                  |
               |     |      |                  |
               +-----+------+-+----------------+
                              |
                              |
                              |   0     1     2          6         8           n
                              |   +-----+-----+----------+---------+-----------+
                              |   |     |     |          |         |           |
                              |   | crc | crc |          |         |           |
  NEGOCIATE_HEADER            +-->+     |     |  cookie  |  MsgId  |  Payload  |
                              |   | len | val |          |         |           |
                              |   |     |     |          |         |           |
                              |   +-----+-----+----------+---------+-----------+
                              |
                              |   0      1
                              |   +------+
                              |   |      |
                              |   | info |
  INFO_CMD                    +-->+      |
                                  | cmd  |
                                  |      |
                                  +------+

\end{minted}
\end{samepage}

A few things we need to properly compute:

* the checksum part is a crc8 computed over everything after ``crc_val`` and bounded by ``crc_len``, in our diagram ``crc_len`` must be equal to ``len(cookie) + len(MsgId) + len(Payload)``. 
* a cookie which is checked against a hardcoded value, 0xDE3Dc846 in our case.
* a MsgId which must be incrementally updated and starts at 1

Here's the python script which can generate valid command packets:

```Python

import sys
import struct
import binascii
import crc8 # https://pypi.org/project/crc8/


def craft_header(args):
    """ Pack a NEGOCIATE_HEADER command """
    msg_id = args.msg_id
    msg_id_len = len(struct.pack(">H", msg_id)) 

    cookie = args.cookie
    cookie_len = len(struct.pack("I", cookie)) 
    
    # compute crc
    hash = crc8.crc8()
    hash.update(struct.pack("I", cookie))
    hash.update(struct.pack(">H", msg_id))
    hash.update(args.arbitrary_payload)
    crc = hash.digest()

    # Pack everything
    header_length = struct.calcsize("BB") + struct.calcsize("BB") + cookie_len + msg_id_len + len(args.arbitrary_payload)
    header = struct.pack("BB", header_length, 0x00)  +\
             struct.pack("B", cookie_len + msg_id_len + len(args.arbitrary_payload)) + crc +\
             struct.pack("I", cookie) +\
             struct.pack(">H", msg_id) +\
             args.arbitrary_payload

    return header

def craft_info(args):
    """ Pack a GET_INFO command """
    info_length = struct.calcsize("BBB")
    info = struct.pack("BBB", info_length, 0x01, args.info_cmd) 
    	# 0x01 for reading b'Space Message Broker v3.1'
        # 0x02 for reading b'L54-8012-5511-0'
        # 0x03 should get the flag, but it's clipped before :(
    return info

def craft_shutdown(args):
    """ Pack a SHUTDOWN command """
    
    shutdown_length = struct.calcsize("BB")
    shutdown = struct.pack("BB", shutdown_length, 0x02)
    return shutdown

def craft_flag(args):
    """ Pack a GET_FLAG command """
    
    flag_length = struct.calcsize("BB")
    flag = struct.pack("BB", flag_length, 0x03)
    return flag

def craft_message(payload):
    """ Pack all messages into a single buffer to send, prefixed by it's length """
    msg = struct.pack("B", 1 + len(payload) ) + payload
    return binascii.hexlify(msg)
    

if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser("Generate valid command packets for the \"Sun? On my Sat?\" challenge")
    parser.add_argument("--cookie", type=lambda x:int(x,0), default=0xDE3Dc846, help="cookie value")
    parser.add_argument("--msg-id", type=lambda x:int(x,0), default=0x1, help="msg id")
    parser.add_argument("--arbitrary-payload", type=lambda x:binascii.unhexlify(x), default=b"", help="hex-encoded arbitrary payload after the header msg (useful to solve the challenge)")

    COMMAND = ["info", "shutdown", "flag"]
    command = parser.add_subparsers(help="COMMAND to generate :{}".format(",".join(COMMAND)), dest="command")

    info = command.add_parser("info", help="GET_INFO command")
    info.add_argument("info_cmd", type=int, help='info_cmd value (only 1 and 2 are accepted)')
    shutdown = command.add_parser("shutdown", help="SHUTDOWN command")
    troll_flag = command.add_parser("flag", help="GET_FLAG command")

    args = parser.parse_args()
    header = craft_header(args)

    if args.command == "info":
        payload = craft_info(args)
    elif args.command == "shutdown":
        payload = craft_shutdown(args)
    elif args.command == "flag":
        payload = craft_flag(args)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Concat and print out
    complete_buffer = header + payload
    message = craft_message(complete_buffer)
    print("message to send : {}".format(message))
```


Now we can generate valid command packets, let's try the ``GET_FLAG`` command:

```
$ python beautiful_gen_packet.py flag
message to send : b'0d0a00069546c83dde00010203'
$ nc sun.satellitesabove.me 5043
Ticket please:
ticket{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
Configuration Server: Running
0d0a00069546c83dde00010203
You fell for it...
[!] Not trying hard enough!
Shutdown
Connection Closed
```

Well that's a bummer...

## handleGetInfo has a dark secret


By looking a bit more around ``GET_INFO``, we end up finding the code path we need to execute in order to get the flag:


```c

static char* CSWTCH_6[] = {
	"Space Message Broker v3.1\0",
	"L54-8012-5511-0\0",
	"FLAG{No, It's not in the firmware, that would have been too easy. But in the patched version it will be located here, so good that should help...?}\0",
}

char * handleGetInfo(uint8_t* info_cmd_packet)
{

  int info_cmd = getStrIdx(info_cmd_packet);
  int clipped_info_cmd = clipStrIdx(info_cmd);
  int decremented_info_cmd = clipped_info_cmd - 1;

  if ((decremented_info_cmd < 3) && ((&CSWTCH_6)[decremented_info_cmd] != NULL)) {
    return (&CSWTCH_6)[decremented_info_cmd];
  }
  
  hangup("Invalid Config Option");
  return NULL;
}
```

If we send a ``GET_INFO`` command with a ``info_cmd`` value set to 3, the program should spit out the wanted flag. However, ``clipStrIdx``  is in the way:

```C
int clipStrIdx(int info_cmd)
{

  int clipped_info_cmd;

  if (2 < info_cmd) {
    return 0;
  }

  clipped_info_cmd = 0;
  if (0 < info_cmd) {
    clipped_info_cmd = info_cmd;
  }

  return clipped_info_cmd;
}
```

if ``info_cmd`` is set to a value greater than 2, it is clipped to zero. So is it another CTF challenge that is broken?
Well no, it is one of these situations where it's dangerous to rely too much on the decompiler view since it may "hides" assembly bugs.


## Annulled branch mon amour

Here's the same function, but disassembled instead of decompiled:

```
**************************************************************
*                          FUNCTION                          *
**************************************************************
undefined clipStrIdx()
undefined         o0:1           <RETURN>
clipStrIdx                                               XREF[1]: handleGetInfo
400016bc 9d e3 bf a0     save       sp,-0x60,sp
400016c0 ac 10 20 03     mov        0x3,l6
400016c4 80 a6 00 16     cmp        i0,l6
400016c8 06 80 00 04     bl         L1
400016cc 80 a6 00 00     _cmp       i0,g0                !delay slot
400016d0 81 c7 e0 08     ret
400016d4 91 e8 00 00     _restore   g0,g0,o0             !delay slot
                     L1                                  XREF[1]: 400016c8(j)  
400016d8 34 80 00 02     bg,a       L2
400016dc ae 10 00 18     _mov       i0,l7                !annulled delay slot				
                     L2                                  XREF[1]: 400016d8(j)  
400016e0 81 c7 e0 08     ret
400016e4 91 ed c0 00     _restore   l7,g0,o0             !delay slot
```

It's less palatable to read, but here's the gist:

* ``i0`` is the input, containing ``info_cmd`` value
* ``g0`` is a global register containing 0
* ``o0`` is the return value

if ``info_cmd`` is greater than 2, ``bl L1`` is not taken and output is set by ``_restore   g0,g0,o0`` to 0.

if ``info_cmd`` is equal to 1 or 2, ``bl L1`` and ``bg,a L2`` are taken and output is set by ``_restore   l7,g0,o0`` to ``i0``.

But what happens if ``info_cmd`` is set to 0?
In that particular case, ``bg,a L2`` is not taken and since this is an annulled branch (see the ``,a`` suffix) the delay slot ``_mov       i0,l7`` in that case is not executed. But, the delay slot in the ``ret`` instruction still set the output from the value of ``l7`` : ``_restore   l7,g0,o0``.


So we have an uninitialized variable vulnerability coming from an annulled delay slot ! Pretty easy to miss if you're not looking hard enough.

However, how is ``%l7`` set ? Now is the time to take out my super register tainting tool: "Text Search" in IDA!

```
.text:400016A8  check_checksum          sll     %o0, 0x18, %l7
.text:400016AC  check_checksum          srl     %l7, 0x18, %l7
.text:400016B0  check_checksum          sub     %l6, %l7, %i0
.text:400016DC  clipStrIdx              mov     %i0, %l7
.text:400016E4  clipStrIdx              restore %l7, %g0, %o0
...
```

The only other non-lib function which touch ``%l7`` is ``check_checksum``, the function responsible to compute the crc8 and checking against the value supplied. So if we send an ``info`` command with a ``info_cmd`` set to 0, it will use the ``crc8`` value as index to access the string array ``CSWTCH_6``.

In order to retrieve the flag, we need to have a payload with a crc value of ``3``, just appending ``f9`` does the trick:

```
+--------+-----------------------------------------------------------------+
|        | +--------------------------------------------+ +--------------+ |
|        | |    |    |    |    |          |     |       | |    |    |    | |
|        | |cmd |cmd |crc |crc |  Cookie  |MsgId|Payload| |cmd |cmd |info| |
| msglen | |len |type|len |val |          |     |       | |len |type|cmd | |
|        | |    |    |    |    |          |     |       | |    |    |    | |
|   0f   | | 0b | 00 | 07 | 03 | de3dc846 |  1  |  f9   | | 03 | 01 | 00 | |
|        | |    |    |    |    |          |     |       | |    |    |    | |
|        | +--------------------------------------------+ +--------------+ |
+--------+-----------------------------------------------------------------+

                           NEGOCIATE_HEADER                    GET_INFO
```

```
$ python beautiful_gen_packet.py --arbitrary-payload="f9" info 0
message to send : b'0f0b00070346c83dde0001f9030100'
$ nc sun.satellitesabove.me 5043
Ticket please:
ticket{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
Configuration Server: Running
0f0b00070346c83dde0001f9030100
flag{YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY}
ACK
```
