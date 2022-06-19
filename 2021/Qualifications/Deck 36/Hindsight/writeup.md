# HACK-A-SAT 2021: Hindsight

* **Category:** Deck 36, Main Engineering
* **Points:** 116
* **Solves:** 32
* **Description:**

> Revenge of the space book!

> Due to budget cutbacks, the optical sensor on your satellite was made with parts from the flea market.
> This sensor is terrible at finding stars in the field of view.
> Readings of individual positions of stars is very noisy.
> To make matters worse, the sensor can't even measure magnitudes of stars either.
> Budget cutbacks aside, make your shareholders proud by identifying which stars the sensor is looking at based on the provided star catalog.

> Connect to the challenge on: early-motive.satellitesabove.me:5002
>
> Using netcat, you might run: nc early-motive.satellitesabove.me 5002
>
> You'll need these files to solve the challenge.
>
> https://static.2021.hackasat.com/hlvjekbpsfaw66nlrzehak730d3g

## Requirements

This writeup will use:

- Python3
- pwntools: <https://github.com/Gallopsled/pwntools>
- Numpy: <https://numpy.org/install/>

## Write-up

_Write-up by Solar Wine team_

This challenge looks like the `spacebook` and `my 0x20` challenge from last year.
Our past writeup is available [here on the team github](https://github.com/solar-wine/quals-writeups/blob/master/Astronomy%2C%20Astrophysics%2C%20Astrometry%2C%20Astrodynamics%2C%20AAAA/My%200x20/%5BOFFICIAL%5D%20writeup.md).

Download the provided file.
We are given a single .txt file with X, Y, Z of 1733 stars.

```shell
$ cat catalog.txt | wc -l
1733

$ head catalog.txt
-0.4959118411830065,    0.46400050493017125,    -0.7340129271334577
0.4225331814601723,     0.8889439220693053,     0.17676089494338368
-0.9285730875015802,    0.11791058235208769,    0.3519220307641658
0.8423213235989879,     0.1951161208284196,     0.5024186373964632
-0.9445204753188363,    -0.04377849555656999,   -0.3255219117513949
-0.13989879333811078,   0.2800045950196423,     0.9497503642486412
0.47167300314561544,    0.6151660752803992,     -0.6317398815396306
0.8874842468400458,     0.4580518278467005,     0.05059876102290792
0.6088647992901426,     0.7401056233549962,     -0.28552989767043113
-0.22756062011542913,   -0.7942289536351562,    0.5633973139626124
```

This is what the service asks us when we provide it with our team ticket:
```shell
$ echo "ticket{echo28410zulu2:GKMF-DGuNjMOrawFCB621Jd7rRgcEysXbmmdqPz8mZTTbjhJZr7O0-roXrrdMNBcUA}" | nc early-motive.satellitesabove.me 5002
Ticket please:
-0.182862,	0.110175,	0.976946
0.063510,	0.172198,	0.983013
0.099288,	-0.176080,	0.979356
-0.055440,	-0.154325,	0.986464
0.125521,	-0.002894,	0.992087
-0.218239,	-0.067029,	0.973591
-0.018649,	0.063052,	0.997836
-0.074830,	0.156673,	0.984812
-0.035332,	0.072418,	0.996748
0.083429,	-0.177233,	0.980626
0.123108,	-0.155649,	0.980111
0.026359,	0.127270,	0.991518
-0.172270,	-0.002115,	0.985048
0.095199,	0.003956,	0.995450
-0.061920,	0.246842,	0.967076
-0.165385,	-0.058480,	0.984494
-0.158970,	-0.110085,	0.981127
-0.164970,	0.059348,	0.984511
-0.046028,	-0.223992,	0.973503
0.020075,	-0.010497,	0.999743
-0.030429,	-0.254281,	0.966652
0.035188,	-0.125803,	0.991431
0.116084,	-0.088886,	0.989254
0.104716,	-0.053336,	0.993071
0.143662,	0.069087,	0.987212
-0.006348,	-0.233888,	0.972243
-0.121062,	-0.123531,	0.984928
0.235419,	-0.009800,	0.971845
-0.130585,	-0.010126,	0.991385
0.111752,	-0.184471,	0.976464
0.064663,	0.160371,	0.984936
0.108471,	0.068876,	0.991711

Index Guesses (Comma Delimited):
```

The description tells us that `This sensor is terrible at finding stars in the field of view`
and `the sensor can't even measure magnitudes of stars either`.
So, the output of the service seems to provide us, only the X,Y and magnitude (?) of stars from a specific position.
We guessed that we couldn't use the magnitude.
And we have to guess the index of at least 10 stars.

We could use our past writeup and modify it a bit.

First, convert catalog.txt into a python array.
```shell
$ (echo -n catalog = [; sed '/^$/d;s/^/[/;s/$/],/' catalog.txt ; echo ']') > catalog.py
```

The distance between two points A and B, in a X, Y, Z reference frame, could be calculated with:

```sqrt((Ax - Bx)^2 + (Ay - By)^2 + (Az - Bz)^2)```

Let's calculate the distance of each star with all others stars and generate it as a new catalogue.

```python
# gen_catalog.py
from math import *
from catalog import *

ROUND = 6

def calc_dist(s1, s2):
  return sqrt((s1[0]-s2[0])**2 + (s1[1]-s2[1])**2 + (s1[2]-s2[2])**2)

i = 0
new_cat = []
for s1 in catalog:
  new_cat.append([s1,[]])
  for s2 in catalog:
    d = round(calc_dist(s1,s2), ROUND)
    new_cat[i][1].append(d)
  i = i + 1

print(new_cat)
```

```shell
$ echo -n "catalog = " > new_catalog.py && python gen_catalog.py >> new_catalog.py
```

Now, how can we match stars?
The catalog is in a celestial reference, each X, Y, Z is a dot on a sphere.
The Euclidean distance between two _very close_ dots on a sphere will be quite the same as the distance between the X,Y dots provided by the service.
We calculate the distance between each stars given by the service and compare with our `new_catalog.py` (with a little delta error allowed).

```python
# solver.py
from math import *
from new_catalog import *
import pwn
import collections, numpy

ROUND = 6
TICKET = b'ticket{echo28410zulu2:GKMF-DGuNjMOrawFCB621Jd7rRgcEysXbmmdqPz8mZTTbjhJZr7O0-roXrrdMNBcUA}'
lines = []

def ticket():
  p.recvuntil(b'Ticket please:')
  p.sendline(TICKET)

def pass_stage(sol):
  p.sendline(sol)
  p.recvuntil(b'Left...') 

def nextr():
  rez = p.recvuntil(b'(Comma Delimited):').split(b'\n')
  lines = []
  for line in rez:
    if b"," in line:
      r = line.split(b',\t')
      x = float(r[0])
      y = float(r[1])
      z = float(r[2])
      lines.append([x, y, z])
  return lines

# only use X,Y this year
def calcdist(s1, s2):
  return sqrt((s1[0]-s2[0])**2 + (s1[1]-s2[1])**2)

# make the catalog of distances from stars provided by the service
def make_d(stars):
  i = 0
  newstars = []
  for s1 in stars:
    newstars.append([s1,[]])
    for s2 in stars:
      d = round(calcdist(s1,s2), ROUND)
      if d != 0:
        newstars[i][1].append(d)

    i = i + 1
  return newstars

def get_sol(stars):
  stars_id = []
  # iterate over 30 privoded stars, because some of them won't match
  for i in range(30):
    findings = []
    f1 = stars[i]
  
    for d1 in f1[1]:
      for s in catalog:
        for ss in s[1]:
          if abs(d1 - ss) < 0.0005: # allowed error (selected randomly after few tries)
            findings.append(s[1].index(ss))

    a = numpy.array(findings)
    c = collections.Counter(a)

    bests = c.most_common(2)
    # sometimes two (or more) stars match a lot
    # only keep a star if it is the only one that match
    if bests[0][1] - bests[1][1] > 4:
      id = str(bests[0][0])
      stars_id.append(id)
      print('found: ' + id)

  return numpy.unique(stars_id)

# stars we found during the quals
# made manually after each stage
#solutions = [
#  ['180', '25',' 277', '311', '479', '51', '693', '852', '944', '979'],
#  ['136', '213', '458', '563', '575', '627', '649', '659', '699', '703', '874', '1014', '1086', '1255'],
#  ['51', '235', '277', '495', '715', '775', '1286', '1479', '1505', '1620', '1701'],
#  ['53', '213', '416', '627', '649', '682', '705', '914', '947', '1086'],
#  ['132', '369', '525', '686', '692', '769', '1145', '1242', '1253', '1402', '1412'],
#]

solutions = []
for i in range(6):
  p = pwn.remote('early-motive.satellitesabove.me', 5002)
  ticket()

  for s in solutions:
    print("sending > " + ','.join(s))
    p.sendline(','.join(s))
    p.recvuntil(b'Left...')

  if i == 5:
    print(p.recvuntil(b'}\n')) # get flag
    p.close()
    exit(0)

  stars = nextr()
  stars = make_d(stars)
  s = get_sol(stars)
  solutions.append(s)
  p.close()
```

Unfortunately, our script is too slow to find the answer before the timeout.
We could improve it, but fortunately the output of the nc command is always the same.
So, we could keep the answer and send it after renewing the connection.
During the CTF, we didn't made a full automated script like the one above.
Instead, we obtained data for each stage sequentially, solved it offline, and then re-connected to send the answer and get the next stage... or flag.

Running the python script, we get:
```shell
$ python solver.py 
[+] Opening connection to early-motive.satellitesabove.me on port 5002: Done
found: 51
found: 180
found: 277
found: 311
found: 479
found: 693
found: 944
found: 992
found: 1392
found: 1470
[*] Closed connection to early-motive.satellitesabove.me port 5002
[+] Opening connection to early-motive.satellitesabove.me on port 5002: Done
sending > 1392,1470,180,277,311,479,51,693,944,992

[...]

[*] Closed connection to early-motive.satellitesabove.me port 5002
[+] Opening connection to early-motive.satellitesabove.me on port 5002: Done
sending > 1392,1470,180,277,311,479,51,693,944,992
sending > 1014,1086,1254,1255,136,213,458,563,627,649,659,699,703,874
sending > 1286,1479,1505,1701,1718,180,235,277,495,51,715,775
sending > 1086,1410,213,416,53,649,682,705,914,947
sending > 1145,1242,1253,132,1412,369,525,686,692,769
b'\nflag{echo28410zulu2:GAtsaKxfAmyoPdfoVBO0JQIPfvv1d8Habn_uqVrBN_0IvhyG9EncFRjOxI5B2YF2ylL-yTgT7ygTvF83SgAI0qY}\n'
[*] Closed connection to early-motive.satellitesabove.me port 5002
```
