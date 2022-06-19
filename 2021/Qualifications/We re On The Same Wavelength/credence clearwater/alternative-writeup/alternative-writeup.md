# HACK-A-SAT 2021: credence clearwater space data systems

* **Category:** We're On the Same Wavelength
* **Points:** 155
* **Solves:** 21
* **Description:**

We've captured this noisy IQ data from a satellite and need to decode it.
Figure out how to filter the noise while maintaining the signal characteristics,
then demodulate and decode the signal to get the flag.
The satellite is transmitting using asynchronous markers in CCSDS space packets and an unknown modulation.

> You'll need these files to solve the challenge.
> https://generated.2021.hackasat.com/noise/noise-yankee334689uniform2.tar.bz2

## Requirements

This writeup will use:

- Python3

## Write-up

_Write-up by Solar Wine team_

Download and decompress the provided file.
We are given a single .txt file, with IQ data.

```shell
$ head iqdata.txt
-0.6335052899144232+0.8380556518484373j
-0.866758746603605+0.743032486821757j
-0.6033535052623433+0.5004989922608711j
-0.966755224778318+0.6286987215417285j
-0.9483743406945173-0.7840476413736899j
-0.6421976703549201-0.3433831018398778j
-0.3927142611159441-0.6723420602388334j
-0.7105855591523836-0.9057824362221066j
0.8473819206478185-0.4712642295218157j
0.7511627021997191-0.695522062052468j
```

Digging a bit in that file, we could assume that the period is 4
```shell
-0.6335052899144232+0.8380556518484373j
-0.866758746603605+0.743032486821757j
-0.6033535052623433+0.5004989922608711j
-0.966755224778318+0.6286987215417285j

-0.9483743406945173-0.7840476413736899j
-0.6421976703549201-0.3433831018398778j
-0.3927142611159441-0.6723420602388334j
-0.7105855591523836-0.9057824362221066j

0.8473819206478185-0.4712642295218157j
0.7511627021997191-0.695522062052468j
0.5955223417562794-0.8175156711057346j
0.767073100534798-0.6780934519924113j

0.4760873653146537-0.5873406211139136j
0.5402906345063136-0.5097431532375803j
0.8902479574216283-1.0028742199846326j
0.7220700797425402-0.6858899458333927j

0.7795050322077074+0.588663682179536j
0.7499736011193275+0.489372102299103j
0.9334603867384117+1.0202588484217752j
0.6050228712697503+0.8774219016762603j

-0.8033676441799906+0.8133398842652187j
-0.6254092691044466+0.6844375765797872j
-0.8522037474879499+0.4738963968136044j
-0.8022529875022965+0.6818740211395661j
...
```

So, we have 1984/4 = 496 periods.
```shell
$ cat iqdata.txt | wc -l
1984
```

If each periods encode 2 bits
the whole file will have 496x2/8 = 124 octets, a decent size for a flag!
Now, it's time to translate IQ data into binary.
We will translate negative value in 0 and positive value in 1.

```python
# solver.py
from textwrap import wrap

f = open('iqdata.txt', 'rb')
samples = f.readlines()
bin = ''
n = 0

for iqstr in samples:
    if n % 4 == 0: # period is 4
        bit = '1'
        if iqstr[0] == ord('-'):
            bit = '0'

        if b'+' in iqstr:
            bit += '1'
        else:
            bit += '0'

        bin += bit
    n += 1

octets = wrap(bin, 8)
print(octets)
```

```bash
$ python solver.py
['01001010', '11011111', '11111101', '01001100', '01010101', '01010100', '11010101',
'01010101', '01010101', '00110100', '00100010', '00101101', '00100100', '00100011',
'00111011', '00111000', '00100100', '00101110', '00101011', '00100000', '00100000',
'01110111', '01110111', '01110001', '01110010', '01111001', '01111000', '00110000',
'00101110', '00101000', '00100010', '00101111', '00110110', '00101100', '01110110',
'01111010', '00010011', '00011101', '00010111', '00011101', '00100100', '00011111',
'00101010', '00100010', '00010000', '00000111', '00101110', '00110110', '00101101',
'01110001', '00101000', '00110001', '00100001', '00100000', '00100010', '00101111',
'01110110', '00100001', '00111000', '00110010', '00010000', '00101100', '00010001',
'00011010', '00011010', '00000011', '01110111', '01110110', '00111001', '00111000',
'00001000', '00011110', '00110100', '00011010', '00101110', '00110111', '00110101',
'00000101', '00101000', '00101110', '00011101', '00000100', '01110011', '00011011',
'00100011', '00011011', '00110111', '00100001', '00110000', '00111001', '00101101',
'00011100', '00000101', '00101001', '00000000', '00101110', '01110100', '00000000',
'00111000', '00110000', '00010010', '00101000', '00010111', '00010100', '01111001',
'00011101', '00011101', '01110000', '00011111', '00011110', '00010111', '00100010',
'01110110', '00101111', '01111000', '00110111', '00000101', '01110111', '00000010',
'00110111', '00010111', '00000101', '00110011', '00111100']
```

A lot of them start with 00 and a few with 01.
If it's a flag, the last one `00111100` should be `01111101` the `}` char.
So, let's transform those pairs of bits:
00 in 01
11 in 11
01 in 00
10 in 10

```python
# solver.py
from textwrap import wrap

f = open('iqdata.txt', 'rb')
samples = f.readlines()
bin = ''
n = 0

for iqstr in samples:
    if n % 4 == 0: # period is 4
        bit = '1'
        if iqstr[0] == ord('-'):
            bit = '0'

        if b'+' in iqstr:
            bit += '1'
        else:
            bit += '0'

        # transform pair of bits
        if bit == '00':
            bit = '01'
        elif bit == '01':
            bit = '00'

        bin += bit
    n += 1

octets = wrap(bin, 8)
result = ''
for octet in octets:
	result += chr(int(octet, 2))

print(result)
```

```bash
$ python solver.py
�ÏüÀqflag{yankee334689uniform2:GLCLaOjfESnrl4itdefo2dyvEmDJJW32xyYNqJnspPinLQ7KgKsduxlMPhUn1UyuFiCA8LL5ONCf2o9sP3VsCPw}
```

Flag is:
flag{yankee334689uniform2:GLCLaOjfESnrl4itdefo2dyvEmDJJW32xyYNqJnspPinLQ7KgKsduxlMPhUn1UyuFiCA8LL5ONCf2o9sP3VsCPw}




