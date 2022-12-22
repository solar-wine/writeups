# HACK-A-SAT 3: Three App Monte

* **Category:** Flight Software - scavenger
* **Points:** 100 divided among teams per flag
* **Description:**

## Write-up

_Write-up by Solar Wine team_

When looking at the files we were able to obtain from the FTP challenge (*150 File Status*)
we noticed the following modules that were not present in our digital twin:

* `mon.so`
* `sms.so`
* `spaceflag.so`

After looking at the code for a few minutes we noticed that all 3 modules had references to a `validPtrs` array, which probably meant they were part of the same challenge.

We were able to quickly identify the communication interfaces for these apps.

### mon.so

The app registers 3 functions:

* *NoOp*: as the name suggests
* *ResetApp*: as the name suggests
* *Debug*: checks whether a pointer value provided as argument is part of the `validPtrs` array, then call it if it is the case

There isn't much more to this app except for one thing: when processing incoming commands, it parses and processes commands with *MsgId* = `SMS_CMD_MID`. This behavior is suspicious as this *MsgId*, as the name suggests, is also subscribed to by `sms.so`, and is not `mon.so`'s subscribed *MsgId* (`0x1f80`).

### sms.so

This app registers 3 functions:

* *NoOp*: as the name suggests
* *ResetApp*: as the name suggests
* *Normal*: processes incoming messages (*Normal* SMS as opposed to *Extended* ones)

While processing incoming messages, a special case can be identified:

```c
OS_printf("received new message\n");

/* If INTERNAL_USE == 1722 and strlen(MESSAGE) > 64: SMS_CMD_MID += 16 */
if ((*(int *)((int)msg + 0xc) == 1722) &&
    (sVar1 = strlen((char *)((int)msg + 0x10)), 0x40 < sVar1)) {
  OS_printf("%d Extended message detected\n",*(undefined4 *)((int)msg + 8));
  SMS_CMD_MID = SMS_CMD_MID + 0x10;
}
```

Any incoming message (command `SMS NORMAL_MSG`) with field `INTERNAL_US` set to `1722` and field `MESSAGE` of at least 65 bytes will increment `SMS_CMD_MID` by 16: from `0x1F70` to `0x1f80`.

From the main command processing loop we can also identify another function that is not being exposed the normal way through `CMDMGR_RegisterFunc`: `SMS_ExtendedCmd`.
```c
int SMS_ExtendedCmd(int param_1)
{
  OS_printf("received Extended command\n");
  OS_printf("%d stored\n",*(undefined4 *)(param_1 + 8));
  OS_printf("%d stored\n",*(undefined4 *)(param_1 + 0xc));
  OS_printf("%s stored\n",param_1 + 0x10);
  SMS_CMD_MID = 0x1f70; /* right here */
  return 1;
}
```
It can only be reached by sending a command with `MsgId = 0x1f80`, which is suspicious
as it is not the usual `MsgId` for this app (`0x1f70`) but ties very well with our
initial analysis of `sms.so`. As we can see from the code, once an extended message is processed,
`SMS_CMD_MID` is reset to its original value.

This led us to believe that we needed to use the interaction between specially-crafted
extended messages to increment `SMS_CMD_MID` whenever we would need it, then reset it later.

### spaceflag.so

This app registers 3 functions:

* *NoOp*: as the name suggests
* *ResetApp*: as the name suggests
* *String*: doesn't do anything useful?

We can see that this app is the one responsible for initializing the `validPtrs` array in `appStart_SPACEFLAG`:
```c
if ((__len == 0xffffffff) && (iVar1 = mprotect(validPtrs,0xffffffff,1), iVar1 == -1)) {
  piVar2 = __errno_location();
  OS_printf("%s sysconf Failure(%d)\n","SPACEFLAG",*piVar2);
                  /* WARNING: Subroutine does not return */
  exit(1);
}
validPtrs = (code **)memalign(__len,__len);
if (validPtrs == (code **)0x0) {
  piVar2 = __errno_location();
  OS_printf("%s memalign Failure(%d)\n","SPACEFLAG",*piVar2);
                  /* WARNING: Subroutine does not return */
  exit(1);
}
for (local_20 = 0; local_20 < 10; local_20 = local_20 + 1) {
  validPtrs[local_20] = (code *)0x0;
}
*validPtrs = SPACEFLAG_Send_Token;
iVar1 = mprotect(validPtrs,__len,1);
```

From here we understand that we have to somehow compute the address of `SPACEFLAG_Send_Token`
then pass it to `mon.so`'s *Debug* command, which will in turn call it and send us the flag:
```c
int SPACEFLAG_Send_Token(void)
{
  size_t sVar1;

  OS_printf("%s received Send Token command, sending (%s)\n","SPACEFLAG",spaceflag_flag);
  /* ... */
  CFE_SB_TimeStampMsg(spaceflag_Token_Pkt);
  CFE_SB_SendMsg(spaceflag_Token_Pkt); /* Bob's your uncle */
  return 1;
}
```

### Putting it all together

In order to get the flag we need to:

* Find a way to compute `SPACEFLAG_Send_Token`'s address
* Send an extended SMS to set `SMS_CMD_MID` to `0x1f80` and be able to communicate with `mon.so` through extended SMS commands
* (Optional) Send a *NoOp* command to `mon.so` using `MsgId = 0x1f80` to ensure it is now reachable
* Send the *Debug* command to `mon.so` with the valid `SPACEFLAG_Send_Token`'s address as argument
* Look for the flag coming from the `SPACEFLAG` app through a `TOKEN_TLM_PKT` packet

This works because `SMS_CMD_MID` is a variable which is shared between `mon.so` and `sms.so`, and `validPtrs` is shared between `mon.so` and `spaceflag.so`.

But we are still missing a way to get (or guess) the address of `SPACEFLAG_Send_Token`

### Leaking pointers

We were initially wondering how to leak a stack/heap pointer in order to try
and guess `SPACEFLAG_Send_Token`'s address but couldn't find any such vulnerability in any of the 3 apps.

Luckily one of our in-house space packets experts remembered that the `CFE_ES`'s
app `SEND_APP_INFO` command can retrieve the address where an application is
loaded through the `START_ADDR` property.
For example, for `SPACEFLAG`, the received `START_ADDR` is the address of function `appStart_SPACEFLAG`.
In Ghidra, this function is loaded at `0x00010de8` and `SPACEFLAG_Send_Token` at `0x00011376`.
This means that when `CFE_ES` replies with `START_ADDR=897564136`, we know that the address of `SPACEFLAG_Send_Token` is `897564136 - 0x00010de8 + 0x00011376 = 0x357fc376`.

In the end, the exploit consisted in:

* Sending command `CFE_ES SEND_APP_INFO` with `APP_NAME = "SPACEFLAG"`
* Receiving packet `CFE_ES APP_INFO_TLM_PKT` and reading `START_ADDR`
* Computing the address of `SPACEFLAG_Send_Token` from it
* Sending command `SMS NORMAL_MSG` with `INTERNAL_USE = 1722` and `MESSAGE = "aaa...a"` (65 times `a`), to set `SMS_CMD_MID` to `0x1f80`
* Sending command `MON NOOP` and verify that we could communicate with `MON` by receiving event `[MON/102.2] No operation command received for MON version 0.1`
* Sending command `MON MON_MSG` with the address of `SPACEFLAG_Send_Token` in `DEBUG`
* Receiving packet `SPACEFLAG TOKEN_TLM_PKT` and reading the flag in it

We got two flags with this solution: `flag{r8ooxvOo}` and `flag{CT06HsbyHGWR8vFY}`.
