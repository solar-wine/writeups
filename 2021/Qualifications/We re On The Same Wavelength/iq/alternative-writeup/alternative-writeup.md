# HACK-A-SAT 2021: iq

* **Category:** We're On the Same Wavelength
* **Points:** 22
* **Solves:** 225
* **Description:**

Convert the provided series of transmit bits into in-phase quadrature samples.

> Connect to the challenge on: unique-permit.satellitesabove.me:5006
> Using netcat, you might run: nc unique-permit.satellitesabove.me 5006

## Requirements

This writeup will use:

- Python3
- pwntools: https://github.com/Gallopsled/pwntools

## Write-up

_Write-up by Solar Wine team_

First, check what the service is asking for:
```shell
$ echo "ticket{oscar27279delta2:GAhUCEqGmxSr_PZM4S1JG5EX9xWaMMSf19E5cMjpiIdw4KmnYxEQH9CCeLutSdJsgg}" | nc unique-permit.satellitesabove.me 5006
Ticket please:
IQ Challenge
   QPSK Modulation   
          Q
          |          
    01    |     11   
    o     |+1   o    
          |          
          |          
    -1    |     +1   
===================== I
          |          
          |          
    00    |     10   
    o     |-1   o    
          |          
          |          
Convert the provided series of transmit bits into QPSK I/Q samples
                  |Start here
                  v
Bits to transmit: 01000011 01110010 01101111 01101101 01110101 01101100 01100101 01101110 01110100 00001010
Provide as interleaved I/Q e.g. 1.0 -1.0 -1.0  1.0 ... 
                                 I    Q    I    Q  ...
Input samples: 
```

We have to transmit a series of bits into QPSK I/Q samples with the following QPSK Modulation:
00 => -1 -1
01 => -1 +1
11 => +1 +1
10 => +1 -1
The series of bits to convert: `01000011 01110010 01101111 01101101 01110101 01101100 01100101 01101110 01110100 00001010`

```python
# solver.py
import pwn

TICKET = b'ticket{oscar27279delta2:GAhUCEqGmxSr_PZM4S1JG5EX9xWaMMSf19E5cMjpiIdw4KmnYxEQH9CCeLutSdJsgg}'

def ticket():
  p.recvuntil(b'Ticket please:')
  p.sendline(TICKET)

def get_challenge():
  p.recvuntil(b'Bits to transmit: ')
  bits = p.recvuntil(b'\n').decode('utf-8')
  p.recvuntil(b'Input samples: ')
  print('received < ' + bits)
  return bits

# just replace 0 by -1.0 and 1 by 1.0
def get_solution(challenge):
  bits = challenge.replace(' ', '')
  bits = bits.replace('0', '-7.0 ')
  bits = bits.replace('1', '1.0 ')
  bits = bits.replace('7', '1')
  bits = bits.strip()
  return bits

p = pwn.remote('unique-permit.satellitesabove.me', 5006)
ticket()
challenge = get_challenge()
solution = get_solution(challenge)
print('sending > ' + solution + '\n')
p.sendline(solution)
print(p.recv().decode('utf-8')) # get the flag

p.close()
```

Running the python script, we get:
```shell
$ python local.py
[+] Opening connection to unique-permit.satellitesabove.me on port 5006: Done
received < 01000011 01110010 01101111 01101101 01110101 01101100 01100101 01101110 01110100 00001010

sending > -1.0 1.0 -1.0 -1.0 -1.0 -1.0 1.0 1.0 -1.0 1.0 1.0 1.0 -1.0 -1.0 1.0 -1.0 -1.0 1.0 1.0 -1.0 1.0 1.0 1.0 1.0 -1.0 1.0 1.0 -1.0 1.0 1.0 -1.0 1.0 -1.0 1.0 1.0 1.0 -1.0 1.0 -1.0 1.0 -1.0 1.0 1.0 -1.0 1.0 1.0 -1.0 -1.0 -1.0 1.0 1.0 -1.0 -1.0 1.0 -1.0 1.0 -1.0 1.0 1.0 -1.0 1.0 1.0 1.0 -1.0 -1.0 1.0 1.0 1.0 -1.0 1.0 -1.0 -1.0 -1.0 -1.0 -1.0 -1.0 1.0 -1.0 1.0 -1.0

You got it! Here's your flag:
flag{oscar27279delta2:GKRwpncyNe2OgU2KD4LEjkjhKiyy-UPvOpJZVXPBw0b1lZl_yO_5BrYfdH1ODuce9MTjzOblNnWIW_wHMMjNrHM}

[*] Closed connection to unique-permit.satellitesabove.me port 5006
```

Flag is:
flag{oscar27279delta2:GKRwpncyNe2OgU2KD4LEjkjhKiyy-UPvOpJZVXPBw0b1lZl_yO_5BrYfdH1ODuce9MTjzOblNnWIW_wHMMjNrHM}
