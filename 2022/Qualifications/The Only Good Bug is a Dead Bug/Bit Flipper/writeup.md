# HACK-A-SAT 3: Bit Flipper

* **Category**: The Only Good Bug is a Dead Bug
* **Points:** 257
* **Solves:** 8
* **Description:**

> We're trying to send our satellite a reset, but some bad guy flashed our reset module with a program to make it really difficult.
>
> We were only able to recover the binary off their computer... Please help.

> You'll need these files to solve the challenge.
>
> https://static.2022.hackasat.com/986wf5z8nf1jax51bmfmhq4n5rdy

## Write-up

_Write-up by Solar Wine team_

The program is using a 32-bit SPARC instruction set to implement a game where the player has a guess a random 16-bit number:

```text
Level 1. FIGHT

Guess: 1
15
Guess: 5
15
Guess: 20
15
Guess: 20
15
```

The number which is returned is a difficulty, which is read from a file named `hardest_rotations.nums` which is not provided.
In fact the guess is not really "just a guess": it is a number which is XOR-ed with the number to be guessed (with a constant 16-bit rotation).

After some tries, a first invariant became clear: if a number has an odd number of 1 in its binary representation, its difficulty is 16. Then, trying to flip each of the 16 bits separately led to the following experimentation result:

```text
input -> xor-cumulated input -> difficulty returned by the remote server
0x0001 -> query 0x0001 -> 15
0x0003 -> query 0x0002 -> 12
0x0006 -> query 0x0004 -> 15
0x000c -> query 0x0008 -> 14
0x0018 -> query 0x0010 -> 15
0x0030 -> query 0x0020 ->  9
0x0060 -> query 0x0040 -> 15
0x00c0 -> query 0x0080 -> 14
0x0180 -> query 0x0100 -> 15
0x0300 -> query 0x0200 -> 12
0x0600 -> query 0x0400 -> 15
0x0c00 -> query 0x0800 -> 14
0x1800 -> query 0x1000 -> 15
0x3000 -> query 0x2000 ->  9
0x6000 -> query 0x4000 -> 15
0xc000 -> query 0x8000 -> 14
```

In this table, "15" alternates every two positions and "14" every four positions.
This gives a strong indication that the content of `hardest_rotations.nums` is very structured.

After some attempts, we successfully managed to generate a file which shares this behavior:

```python
import itertools

def rol16(value: int, shift: int) -> int:
    return ((value << shift) & 0xffff) | (value >> (16 - shift))

hardest_rotations = [None] * 0x10000
for iter_count in range(16):
    base_value = hardest_rotations.index(None, 1)
    possible_shifts = set()
    for bit1 in range(16):
        for bit2 in range(bit1 + (1 << iter_count), 16, 1 << iter_count):
            possible_shifts.add((1 << bit1) ^ (1 << bit2))
        possible_shifts.add(rol16(base_value, bit1) ^ base_value)
    for val1, val2 in itertools.combinations(possible_shifts, 2):
        new_shift = val1 ^ val2
        if new_shift not in possible_shifts:
            possible_shifts.add(new_shift)
            for val in list(possible_shifts):
                possible_shifts.add(new_shift ^ val)

    for shift in possible_shifts:
        assert hardest_rotations[base_value ^ shift] is None
        hardest_rotations[base_value ^ shift] = 16 - iter_count

    print(f"{iter_count} (difficulty {16 - iter_count}): from {base_value:#x}: {len(possible_shifts)}={len(possible_shifts):#x} values")

with open("hardest_rotations.nums", "wb") as f:
    for diff in hardest_rotations[1:]:
        f.write(f"{diff:02d}\n".encode())
```

While generating the file, this script displayed the number which was used to initiate the search of each difficulty level:

```text
 0 (difficulty 16): from 0x1: 32768=0x8000 values
 1 (difficulty 15): from 0x3: 16384=0x4000 values
 2 (difficulty 14): from 0x5: 8192=0x2000 values
 3 (difficulty 13): from 0xf: 4096=0x1000 values
 4 (difficulty 12): from 0x11: 2048=0x800 values
 5 (difficulty 11): from 0x33: 1024=0x400 values
 6 (difficulty 10): from 0x55: 512=0x200 values
 7 (difficulty  9): from 0xff: 256=0x100 values
 8 (difficulty  8): from 0x101: 128=0x80 values
 9 (difficulty  7): from 0x303: 64=0x40 values
10 (difficulty  6): from 0x505: 32=0x20 values
11 (difficulty  5): from 0xf0f: 16=0x10 values
12 (difficulty  4): from 0x1111: 8=0x8 values
13 (difficulty  3): from 0x3333: 4=0x4 values
14 (difficulty  2): from 0x5555: 2=0x2 values
15 (difficulty  1): from 0xffff: 1=0x1 values
```

This gave a winning strategy for the game: according to the difficulty returned by the server, enter the given number!

```python
guess_for_value = {
    16: 1,      15: 3,      14: 5,      13: 0xf,
    12: 0x11,   11: 0x33,   10: 0x55,    9: 0xff,
     8: 0x101,   7: 0x303,   6: 0x505,   5: 0xf0f,
     4: 0x1111,  3: 0x3333,  2: 0x5555,  1: 0xffff,
}
```

With this, getting the flag only required playing the game three times.

```text
Level 1. FIGHT
    0x0001 -> 13
    0x000f -> 11
    0x0033 ->  6
    0x0505 ->  5
    0x0f0f ->  4
    0x1111 ->  2
    0x5555 ->  1
    0xffff -> FOUND
Reset sequence round 1 completed.
Level 2. FIGHT
    0x0001 -> 13
    0x000f -> 12
    0x0011 -> 11
    0x0033 -> 10
    0x0055 ->  8
    0x0101 ->  7
    0x0303 ->  6
    0x0505 ->  5
    0x0f0f -> FOUND
Reset sequence round 2 completed.
Level 3. FIGHT
    0x0001 -> 15
    0x0003 -> 14
    0x0005 -> 13
    0x000f -> 12
    0x0011 -> 11
    0x0033 -> 10
    0x0055 ->  9
    0x00ff ->  8
    0x0101 ->  7
    0x0303 ->  6
    0x0505 ->  5
    0x0f0f ->  4
    0x1111 ->  3
    0x3333 ->  2
    0x5555 ->  1
    0xffff -> FOUND
Reset sequence round 3 completed.
Resetting satellite: flag{uniform645260quebec3:GNkVBa64TqKVsJhK6Ss99Cw2gPnH2Gx-eWEjZ87o6BHrwH74eRwQDKT67Gkun3p84U-3BGaW9JstLgXeaNjwlpE}
```
