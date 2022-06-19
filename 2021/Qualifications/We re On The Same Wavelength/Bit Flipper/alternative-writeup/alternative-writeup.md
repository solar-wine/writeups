# HACK-A-SAT 2021: Bit Flipper

* **Category:** We're On the Same Wavelength
* **Points:** 36
* **Solves:** 130
* **Description:**

mom said it's my turn flipping bits in the thermal protection system

dad says don't touch the thermostat

> Connect to the challenge on: dying-word.satellitesabove.me:5004
> Using netcat, you might run: nc dying-word.satellitesabove.me 5004
> You'll need these files to solve the challenge. https://static.2021.hackasat.com/376raoi16r2vny7j34y4pkd1joae

## Requirements

This writeup will use :

- Python3

## Write-up

_Write-up by Solar Wine team_

Inside the provided file, we got an encoded.bin program.
```shell
$ cat encoded.bin 
# Temper�ature Se�nsor
# IRf temper�ature ab�ove/belopw threshKold, dea]ctivate/[activate� heater
Timport sPys

def +readTemp=(temp,st�ate):
  �  if temBp < 15 a�nd not s~tate:
  �      prFint("Tem�p: %.2fC� Activatying heather"%tempL)
      �  return� 1
    e�lif temp4 > 35 anid state:M
       � print("dTemp: %.v2fC Deac�tivating� heater"�%temp)
 �       r@eturn 0
�    else�:
      ?  return� state

�
```

```shell
$ cat encoded.bin | xxd
00000000: 2320 5465 6d70 6572 b661 7475 7265 2053  # Temper.ature S
00000010: 65b5 6e73 6f72 0a23 2049 5266 2074 656d  e.nsor.# IRf tem
00000020: 7065 72b9 6174 7572 6520 6162 ba6f 7665  per.ature ab.ove
00000030: 2f62 656c 6f70 7720 7468 7265 7368 4b6f  /belopw threshKo
00000040: 6c64 2c20 6465 615d 6374 6976 6174 652f  ld, dea]ctivate/
00000050: 5b61 6374 6976 6174 65ae 2068 6561 7465  [activate. heate
00000060: 720a 5469 6d70 6f72 7420 7350 7973 0a0a  r.Timport sPys..
00000070: 6465 6620 2b72 6561 6454 656d 703d 2874  def +readTemp=(t
00000080: 656d 702c 7374 9f61 7465 293a 0a20 20ac  emp,st.ate):.  .
00000090: 2020 6966 2074 656d 4270 203c 2031 3520    if temBp < 15 
000000a0: 61d4 6e64 206e 6f74 2073 7e74 6174 653a  a.nd not s~tate:
000000b0: 0a20 2092 2020 2020 2020 7072 4669 6e74  .  .      prFint
000000c0: 2822 5465 6de3 703a 2025 2e32 6643 f120  ("Tem.p: %.2fC. 
000000d0: 4163 7469 7661 7479 696e 6720 6865 6174  Activatying heat
000000e0: 6865 7222 2574 656d 704c 290a 2020 2020  her"%tempL).    
000000f0: 2020 8520 2072 6574 7572 6efa 2031 0a20    .  return. 1. 
00000100: 2020 2065 f36c 6966 2074 656d 7034 203e     e.lif temp4 >
00000110: 2033 3520 616e 6964 2073 7461 7465 3a4d   35 anid state:M
00000120: 0a20 2020 2020 2020 8020 7072 696e 7428  .       . print(
00000130: 2264 5465 6d70 3a20 252e 7632 6643 2044  "dTemp: %.v2fC D
00000140: 6561 63c6 7469 7661 7469 6e67 8120 6865  eac.tivating. he
00000150: 6174 6572 22d9 2574 656d 7029 0a20 a220  ater".%temp). . 
00000160: 2020 2020 2020 7240 6574 7572 6e20 300a        r@eturn 0.
00000170: d620 2020 2065 6c73 65cb 3a0a 2020 2020  .    else.:.    
00000180: 2020 3f20 2072 6574 7572 6efa 2073 7461    ?  return. sta
00000190: 7465 0a0a c2                             te...
```

It seems that, every 8 bytes, a byte is appended.

The service is asking us to ionize (change the value) of 3 bits inside the program to make the spacecraft exceeded its operating temperature.
But an error detecting and correcting (secded) occurs.

After a bit of research, the correcting system is an implementation of (72, 64) hamming code.
Let's make a 72, 64 hamming code implementation :
```python
# fec_secded7264.py
# based on : http://www.ecs.umass.edu/ece/koren/FaultTolerantSystems/simulator/Hamming/HammingCodes.html
#
def fec_secded7264_compute_parity(string):
    s = list(map(int, list(''.join(map(lambda x: str(bin(ord(x)))[2:].zfill(8), list(string)))[::-1])))
    P0 = s[0] ^ s[1] ^ s[3] ^ s[4] ^ s[6] ^ s[8] ^ s[10] ^ s[11] ^ s[13] ^ s[15] ^ s[17] ^ s[19] ^ s[21] ^ s[23] ^ s[25] ^ s[26] ^ s[28] ^ s[30] ^ s[32] ^ s[34] ^ s[36] ^ s[38] ^ s[40] ^ s[42] ^ s[44] ^ s[46] ^ s[48] ^ s[50] ^ s[52] ^ s[54] ^ s[56] ^ s[57] ^ s[59] ^ s[61] ^ s[63]
    P1 = s[0] ^ s[2] ^ s[3] ^ s[5] ^ s[6] ^ s[9] ^ s[10] ^ s[12] ^ s[13] ^ s[16] ^ s[17] ^ s[20] ^ s[21] ^ s[24] ^ s[25] ^ s[27] ^ s[28] ^ s[31] ^ s[32] ^ s[35] ^ s[36] ^ s[39] ^ s[40] ^ s[43] ^ s[44] ^ s[47] ^ s[48] ^ s[51] ^ s[52] ^ s[55] ^ s[56] ^ s[58] ^ s[59] ^ s[62] ^ s[63]
    P2 = s[1] ^ s[2] ^ s[3] ^ s[7] ^ s[8] ^ s[9] ^ s[10] ^ s[14] ^ s[15] ^ s[16] ^ s[17] ^ s[22] ^ s[23] ^ s[24] ^ s[25] ^ s[29] ^ s[30] ^ s[31] ^ s[32] ^ s[37] ^ s[38] ^ s[39] ^ s[40] ^ s[45] ^ s[46] ^ s[47] ^ s[48] ^ s[53] ^ s[54] ^ s[55] ^ s[56] ^ s[60] ^ s[61] ^ s[62] ^ s[63]
    P3 = s[4] ^ s[5] ^ s[6] ^ s[7] ^ s[8] ^ s[9] ^ s[10] ^ s[18] ^ s[19] ^ s[20] ^ s[21] ^ s[22] ^ s[23] ^ s[24] ^ s[25] ^ s[33] ^ s[34] ^ s[35] ^ s[36] ^ s[37] ^ s[38] ^ s[39] ^ s[40] ^ s[49] ^ s[50] ^ s[51] ^ s[52] ^ s[53] ^ s[54] ^ s[55] ^ s[56]
    P4 = s[11] ^ s[12] ^ s[13] ^ s[14] ^ s[15] ^ s[16] ^ s[17] ^ s[18] ^ s[19] ^ s[20] ^ s[21] ^ s[22] ^ s[23] ^ s[24] ^ s[25] ^ s[41] ^ s[42] ^ s[43] ^ s[44] ^ s[45] ^ s[46] ^ s[47] ^ s[48] ^ s[49] ^ s[50] ^ s[51] ^ s[52] ^ s[53] ^ s[54] ^ s[55] ^ s[56]
    P5 = s[26] ^ s[27] ^ s[28] ^ s[29] ^ s[30] ^ s[31] ^ s[32] ^ s[33] ^ s[34] ^ s[35] ^ s[36] ^ s[37] ^ s[38] ^ s[39] ^ s[40] ^ s[41] ^ s[42] ^ s[43] ^ s[44] ^ s[45] ^ s[46] ^ s[47] ^ s[48] ^ s[49] ^ s[50] ^ s[51] ^ s[52] ^ s[53] ^ s[54] ^ s[55] ^ s[56]
    P6 = s[57] ^ s[58] ^ s[59] ^ s[60] ^ s[61] ^ s[62] ^ s[63]
    P7 = s[0] ^ s[1] ^ s[2] ^ s[3] ^ s[4] ^ s[5] ^ s[6] ^ s[7] ^ s[8] ^ s[9] ^ s[10] ^ s[11] ^ s[12] ^ s[13] ^ s[14] ^ s[15] ^ s[16] ^ s[17] ^ s[18] ^ s[19] ^ s[20] ^ s[21] ^ s[22] ^ s[23] ^ s[24] ^ s[25] ^ s[26] ^ s[27] ^ s[28] ^ s[29] ^ s[30] ^ s[31] ^ s[32] ^ s[33] ^ s[34] ^ s[35] ^ s[36] ^ s[37] ^ s[38] ^ s[39] ^ s[40] ^ s[41] ^ s[42] ^ s[43] ^ s[44] ^ s[45] ^ s[46] ^ s[47] ^ s[48] ^ s[49] ^ s[50] ^ s[51] ^ s[52] ^ s[53] ^ s[54] ^ s[55] ^ s[56] ^ s[57] ^ s[58] ^ s[59] ^ s[60] ^ s[61] ^ s[62] ^ s[63] ^ P0 ^ P1 ^ P2 ^ P3 ^ P4 ^ P5 ^ P6
    parity = f'{int("".join(map(str, [P0, P1, P2, P3, P4, P5, P6, P7]))[::-1], 2):02x}'

    return bytes.fromhex(parity)

def fec_secded7264_encode(string):
    encoded = b''
    while (len(string) >= 8):
        block = string[0:8]
        string = string[8:]
        parity = fec_secded7264_compute_parity(block)
        encoded += block.encode('utf-8') + parity

    if (len(string)):
        block = string.ljust(8, "\x00")
        parity = fec_secded7264_compute_parity(block)
        encoded += string.encode('utf-8') + parity
    
    return encoded

def fec_secded7264_decode_lazy(string):
    decoded = b''
    while (len(string) >= 9):
        block = string[0:8]
        string = string[9:]
        decoded += block

    if (len(string)):
        block = string[:-1]
        decoded += block

    return decoded
```

We would like to change the `return 0` by a `return 1`, then the heater never stop.
Use the fec_secded7264 to find which bits to ionize.
```python
# solver.py
from fec_secded7264 import *

origin = "eturn 0\n" # the original 8 bytes which contain the return 0
wanted = "eturn 1\n" # the wanted 8 bytes with a return 1

print(origin.encode('utf-8'))
print(b"parity: " + fec_secded7264_compute_parity(origin))
print(wanted.encode('utf-8'))
print(b"parity: " + fec_secded7264_compute_parity(wanted))
```

Running the script we got:
```shell
$ python solver.py 
b'eturn 0\n'
b'parity: \xd6'
b'eturn 1\n'
b'parity: \xdb'
```

The parity found from the original string is `0xd6` and that's correct.
The parity from the wanted string is `0xdb`.
0xd6 = 11010110
0xdb = 11011011

We could ionize 3 bits of `11010110` to change it to `11011011`.
Then the correcting system will think that the program got an error and it will `correct` the 0 into a 1.

Solution is:
```shell
Bitflip #1

Select byte to ionize (0-404): 368

Select bit to ionize (0-7): 0

Bitflip #2

Select byte to ionize (0-404): 368

Select bit to ionize (0-7): 2

Bitflip #3

Select byte to ionize (0-404): 368

Select bit to ionize (0-7): 3
```
