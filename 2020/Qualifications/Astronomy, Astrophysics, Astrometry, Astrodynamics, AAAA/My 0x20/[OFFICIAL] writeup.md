# SPACE SECURITY CHALLENGE 2020 HACK-A-SAT: My 0x20

* **Category:** Astronomy, Astrophysics, Astrometry, Astrodynamics, AAAA
* **Points:** 142
* **Solves:** 24
* **Description:**

> Hah, yeah we're going to do the hard part anyways! Glue all previous parts together by identifying these stars based on the provided catalog. Match the provided boresight refence vectors to the catalog refence vectors and tell us our attitude.
>
> Note: The catalog format is unit vector (X,Y,Z) in a celestial reference frame and the magnitude (relative brightness)
>
> Connect to the challenge on spacebook.satellitesabove.me:5015 . Using netcat, you might run nc spacebook.satellitesabove.me 5015
>
> [Download](https://generated.2020.hackasat.com/myspace/myspace-whiskey42551whiskey.tar.bz2)

## Write-up

_Write-up by Solar Wine team_


Inside the tarball we got a test.txt file with X, Y, Z and magnitude of 2500 stars.
``` {.text fontsize="\scriptsize"} 
$ head test.txt 
-0.8882608014194397,	0.44134505673417335,	-0.12730785348125204,	549.852851299719
-0.3390064785987893,	0.7839854357768783,	0.5200398484325859,	549.6114788231387
0.3818422687775949,	-0.9185613112933841,	-0.10218414343604232,	549.5032313143548
0.7164710254748454,	-0.584280946382752,	0.3811627544095818,	549.4760726460809
0.4581375854452007,	-0.30990873193224816,	-0.8331065542141578,	549.2485100045466
-0.01024392531775858,	0.8300071954123204,	0.5576586030519555,	549.2056889196198
0.038029570197494436,	-0.9310124114282005,	0.3630008836865842,	549.0641302516602
-0.5533457672995926,	0.8172069485090612,	-0.161187050100602,	548.9423706959843
-0.9538126880237273,	0.0852010268733563,	-0.28806620972387137,	548.5438666941857
-0.3209163118673173,	0.013014250692831925,	0.9470181360757475,	548.5162645606902
```

```
$ nc myspace.satellitesabove.me 5016
0.060122,	-0.150465,	0.986785,	22.727474
-0.109832,	-0.067411,	0.991662,	22.333473
-0.045802,	0.058479,	0.997237,	22.223271
0.100712,	0.068262,	0.992571,	22.178468
-0.044828,	-0.046502,	0.997912,	11.322817
0.112874,	-0.088058,	0.989700,	11.127700
-0.010169,	0.130648,	0.991377,	11.076530
0.007961,	0.110731,	0.993819,	11.284805
-0.085996,	-0.032651,	0.995760,	11.521133
0.094996,	0.136541,	0.986069,	11.459429
0.072782,	-0.109259,	0.991345,	11.033900
-0.003755,	0.155835,	0.987776,	10.114427
0.136234,	-0.044629,	0.989671,	10.866810
-0.085711,	0.029520,	0.995883,	10.030610
0.097742,	0.047320,	0.994086,	10.294288
-0.049144,	-0.030339,	0.998331,	9.731732
0.120913,	0.059759,	0.990863,	8.836118
-0.118723,	-0.123024,	0.985277,	8.744872
-0.121255,	0.107121,	0.986824,	9.332223
-0.062622,	-0.037891,	0.997318,	8.875999
-0.040054,	0.091945,	0.994958,	8.678135
0.057317,	-0.033120,	0.997807,	9.356773
0.028940,	0.094192,	0.995133,	8.301271

Index Guesses (Comma Delimited):
```

The output of the nc command, tells us the X, Y, Z and magnitude (?) of stars from a specific position.
We have to guess the index of 5 stars.
We couldn't use the magnitude this time (cf SpaceBook task).
But we could calculate the distance between each stars given and compare with the test.txt provided.

First, convert test.txt into a python array (cf catalog.py, we just sed-ed test.txt)
Distance in two dot A and B, in a X, Y, Z plan, could be calculated with: sqrt((Ax - Bx)^2 + (Ay - By)^2 + (Az - Bz)^2)
Let's calculate the distance of each star with all others stars and generate it as a catalogue.

cf: gen_cat.py
```python
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

```console
$ echo -n "catalog = " > new_cat.py && python gen_cat.py >> new_cat.py 
```

Then make a python script that will parse the output of nc command.
Calculate the distance between each stars given.
Compare with our new_cat.py catalogue.

cf: sol.py
```python
from math import *
from new_cat import *
import pwn
import collections, numpy

ROUND = 6
TICKET = b"ticket{whiskey42551whiskey:GOjJ2Rxfvdcha8Py0lOxbyFNOJOI3At8TYXG3j_DUyIlO5CsMTWlWl7crBfWJk9N1A}"
lines = []

def ticket():
  p.recvuntil(b'Ticket please')
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
      m = float(r[3])
      lines.append([x, y, z, m])
  return lines

def calcdist(s1, s2):
  return sqrt((s1[0]-s2[0])**2 + (s1[1]-s2[1])**2 + (s1[2]-s2[2])**2)

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
  for i in range(5):
    findings = []
    f1 = stars[i]
  
    for d1 in f1[1]:
      for s in catalog:
        if d1 in s[1]:
          findings.append(s[1].index(d1))

    a = numpy.array(findings)
    c = collections.Counter(a)
    id = c.most_common(1)[0][0]
    stars_id.append(str(id))
    print("found: " + str(id))

  return stars_id

solutions = []
for i in range(6):
  p = pwn.remote('myspace.satellitesabove.me',5016)
  ticket()
 
  for s in solutions:
    print("sending > " + ','.join(s))
    p.sendline(','.join(s))
    p.recvuntil(b'Left...')

  if i == 5:
   print(p.recv())
   exit(0)

  stars = nextr()
  stars = make_d(stars)
  s = get_sol(stars)
  solutions.append(s)
  
```

Unfortunately, our script is too slow to find the answer before the timeout.
Fortunately, the output of the nc command is always the same, so you could keep the answer and send it after renewing the connection.
During the CTF, we didn't made a full automated script like the one above, we just solved each stage and send answer after.

Running the python script, we get: 
```
$ python sol.py
[...]
[+] Opening connection to myspace.satellitesabove.me on port 5016: Done
sending > 90,299,317,411,568
sending > 20,83,384,668,982
sending > 83,146,174,389,428
sending > 82,276,314,369,441
sending > 52,116,398,484,490
b'\nflag{whiskey42551whiskey:GMOr6fOnIXcmYpOHJCYMSZ6Vp4QvG559Hb6v5OTs78Rhdm7BO3xRS0zxGE_fxReHmPEmDHeOegqToHMK5iKIwo4}\n
'
```

