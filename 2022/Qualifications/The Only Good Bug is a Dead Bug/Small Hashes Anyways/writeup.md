# HACK-A-SAT 3: Small Hashes Anyways

* **Category:** The Only Good Bug is a Dead Bug
* **Points:** 73
* **Solves:** 58
* **Description:**

> Micro hashes for micro blaze ¯\_(ツ)_/¯

> You'll need these files to solve the challenge.
> 
> - https://generated.2022.hackasat.com/small_hashes_anyways/small_hashes_anyways-yankee957187romeo3.tar.bz2
> - https://static.2022.hackasat.com/hcx6yv4mw0sgrax3kea36v5vy1vi

## Requirements

This writeup will use:

- Python3
- pwntools: <https://github.com/Gallopsled/pwntools>

## Write-up

_Write-up by Solar Wine team_

The challenge is an ELF MicroBlaze 32-bit.
We were also provided an archive with all the libraries required to run this program.

```console
$ file small_hashes_anyways 
small_hashes_anyways: ELF 32-bit MSB executable, Xilinx MicroBlaze 32-bit RISC, version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, for GNU/Linux 3.2.0, stripped
```

To run the program, use qemu and link to it all the libraries.

```console
$ QEMU_LD_PREFIX=./microblaze-linux LD_LIBRARY_PATH=./microblaze-linux/lib qemu-microblaze ./small_hashes_anyways
small hashes anyways:
test
wrong length wanted 112 got 4
```

It seems that the program is waiting a string of 112 chars.

```console
$ python -c 'print("a"*112)' | QEMU_LD_PREFIX=./microblaze-linux LD_LIBRARY_PATH=./microblaze-linux/lib qemu-microblaze ./small_hashes_anyways
small hashes anyways: 
mismatch 1 wanted 1993550816 got 3904355907
```

A 112 chars string looks like a flag.
Let's try to put the beginning of a flag:

```console
$ python -c 'print("flag{yankee957187romeo3:"+"a"*88)' | QEMU_LD_PREFIX=./microblaze-linux LD_LIBRARY_PATH=./microblaze-linux/lib qemu-microblaze ./small_hashes_anyways
small hashes anyways: 
mismatch 25 wanted 4293277456 got 770421485
```

Perfect, it seems that we could bruteforce each char one by one.

Running the python script we get:

```console
$ python solver.py
sending > flag{yankee957187romeo3:0.......................................................................................
sending > flag{yankee957187romeo3:1.......................................................................................
sending > flag{yankee957187romeo3:2.......................................................................................
sending > flag{yankee957187romeo3:3.......................................................................................
sending > flag{yankee957187romeo3:4.......................................................................................


...

sending > flag{yankee957187romeo3:GFrYdvdroY6qM_Cw0RxxUgIbYZ1g0AcfLzCi5GQeGj8LbjDx-vP073tareu4XrsXVDieStMacTyqefeHwnt956a.
sending > flag{yankee957187romeo3:GFrYdvdroY6qM_Cw0RxxUgIbYZ1g0AcfLzCi5GQeGj8LbjDx-vP073tareu4XrsXVDieStMacTyqefeHwnt956b.
sending > flag{yankee957187romeo3:GFrYdvdroY6qM_Cw0RxxUgIbYZ1g0AcfLzCi5GQeGj8LbjDx-vP073tareu4XrsXVDieStMacTyqefeHwnt956c.

flag > flag{yankee957187romeo3:GFrYdvdroY6qM_Cw0RxxUgIbYZ1g0AcfLzCi5GQeGj8LbjDx-vP073tareu4XrsXVDieStMacTyqefeHwnt956c}
```
