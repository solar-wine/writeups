# SPACE SECURITY CHALLENGE 2020 HACK-A-SAT: My 0x20

* **Category:** Astronomy, Astrophysics, Astrometry, Astrodynamics, AAAA
* **Points:** 142
* **Solves:** 24
* **Description:**

> myspace.satellitesabove.me:5016
>
> [Download](https://generated.2020.hackasat.com/myspace/myspace-whiskey42551whiskey.tar.bz2)
>
> This social media app is back with a vengeance!

## Write-up

_Write-up by Solar Wine team_


The tarball contains a single file, `test.txt`, which is a catalog of stars in (X, Y, Z, Magnitude) format.

In order to quickly use it in a `Python` script, a conversion is first made to have it as a matrix:

```bash
(echo -n catalog = [; sed '/^$/d;s/^/[/;s/$/],/' test.txt ; echo ']') > has_catalog.py
```

When connecting to the service, we get the following message:

```
nc myspace.satellitesabove.me 5016
Ticket please:
ticket{whiskey42551whiskey:GOjJ2Rxfvdcha8Py0lOxbyFNOJOI3At8TYXG3j_DUyIlO5CsMTWlWl7crBfWJk9N1A}  ^C                                                         
0.060122,       -0.150465,      0.986785,       22.727474
-0.109832,      -0.067411,      0.991662,       22.333473
-0.045802,      0.058479,       0.997237,       22.223271
0.100712,       0.068262,       0.992571,       22.178468
-0.044828,      -0.046502,      0.997912,       11.322817
0.112874,       -0.088058,      0.989700,       11.127700
-0.010169,      0.130648,       0.991377,       11.076530
0.007961,       0.110731,       0.993819,       11.284805
-0.085996,      -0.032651,      0.995760,       11.521133
0.094996,       0.136541,       0.986069,       11.459429
0.072782,       -0.109259,      0.991345,       11.033900
-0.003755,      0.155835,       0.987776,       10.114427
0.136234,       -0.044629,      0.989671,       10.866810
-0.085711,      0.029520,       0.995883,       10.030610
0.097742,       0.047320,       0.994086,       10.294288
-0.049144,      -0.030339,      0.998331,       9.731732
0.120913,       0.059759,       0.990863,       8.836118
-0.118723,      -0.123024,      0.985277,       8.744872
-0.121255,      0.107121,       0.986824,       9.332223
-0.062622,      -0.037891,      0.997318,       8.875999
-0.040054,      0.091945,       0.994958,       8.678135
0.057317,       -0.033120,      0.997807,       9.356773
0.028940,       0.094192,       0.995133,       8.301271

Index Guesses (Comma Delimited):
```

The star identification problem is the [subgraph isomorphism problem](https://en.wikipedia.org/wiki/Subgraph_isomorphism_problem) with complete graphs.
While the problem is NP-complete, some heuristics can be used to speed up the solving, VF2 is a well known algorithm to solve such isomorphism problem.
A lot of algorithms exist for the star identification problem: Angle, Interior Angle, Spherical Triangle, Planar Triangle, Pyramid, Composite Pyramid, etc.

In our case, the catalog contains _only_ 2500 stars, as a result, solving the challenge might not require to implement a state-of-the-art algorithm.
Since the attitude of the observation device doesn't affect the distances on the unit sphere used for the coordinate system, we want to match star distances between the observation and the reference catalog.
To do so, distances were empirically rounded so that the noise from the observation does not affect the distance comparison.

The proposed approach is as follows:

  - compute the maximum distance between two stars in the list given by the server
  - while doing so, generate a list of all distances for all stars given by the server
  - generate a proximity catalog that lists for each star in the catalog, all the stars whose distance is less than the distance previously obtained
  - while doing so, generate a list of all distances for these nearest stars
  - finally, for each star given by the server, find the candidate stars in the proximity catalog with matching distances
  - stars with 100% match are likely to be the one we want to identify

Since it worked on the first try, no additional refining has been done on the algorithm.
Although it should be possible to filter out incorrectly matched stars by creating a graph of matched stars and comparing it to the graph of the stars given by the server.
The complete identification of all stars can also be obtained using these generated graphs.

The following implementation can be used to solve the challenge:

Note: during the challenge, a lower threshold than 100% was used, with a higher precision for the rounding of the distance, and stars were filtered out manually.
The outputs from this script might differ from the ones used to get the flag that validated the challenge.

```python
#!/usr/bin/env python3

import math
import pwn
from has_catalog import *

TICKET = b"ticket{whiskey42551whiskey:GOjJ2Rxfvdcha8Py0lOxbyFNOJOI3At8TYXG3j_DUyIlO5CsMTWlWl7crBfWJk9N1A}"
ROUND_VAL = 5

def get_maxnorm(observed):
    maxnorm = 0
    allnorm = []
    for curidx1, (x1,y1,z1,m1) in enumerate(observed):
        curstar = []
        for curidx2, (x2,y2,z2,m2) in enumerate(observed):
            if curidx2 == curidx1:
                continue
            val1 = (x2-x1)**2 + (y2-y1)**2 + (z2-z1)**2
            curstar.append([curidx2, round(math.sqrt(val1), ROUND_VAL), x2, y2, z2])
            if val1 > maxnorm:
                maxnorm = val1
        allnorm.append(curstar)
    return maxnorm, allnorm

def get_proxy_arr(catalog, maxnorm, minlen):
    maxnorm *= 1.1
    proxarr = []
    for curidx1, (x1,y1,z1,a) in enumerate(catalog):
        proximity = []
        for curidx2, (x2,y2,z2,b) in enumerate(catalog):
            if curidx2 == curidx1:
                continue
            val1 = (x2-x1)**2 + (y2-y1)**2 + (z2-z1)**2
            if val1 <= maxnorm:
                proximity.append([curidx2, round(math.sqrt(val1), ROUND_VAL), x2, y2, z2])
        if len(proximity) >= minlen:
            proxarr.append(proximity)
    return proxarr      

def get_stars(proxarr, allnorm):
    starsfound = []
    for refidx, arr in enumerate(proxarr):
        for obsidx, stari in enumerate(allnorm):
            allfound = True
            for staro, dist, x, y, z in stari:
                found = False
                for starref, dist2, x2, y2, z2 in arr:
                    if dist == dist2:
                        found = True
                        break
                if not found:
                    allfound = False
                    break
            if allfound:
                #print("found: " + str(obsidx) + " as " + str(refidx))
                starsfound.append(refidx)
    return ','.join([str(x) for x in starsfound])

def ticket():
    p.recvuntil(b'Ticket please')
    p.sendline(TICKET)

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

p = pwn.remote('myspace.satellitesabove.me',5016)
ticket()

running = True
while running:
    stars = nextr()

    maxdist, distarr = get_maxnorm(stars)
    proxarr = get_proxy_arr(catalog, maxdist, len(stars))
    sol = get_stars(proxarr, distarr)

    p.sendline(sol)
    data = p.recvuntil('\n')
    data = p.recvuntil('\n')

    if data.startswith(b'0 Left'):
        while True:
            try:
                print(p.recv())
            except:
                running = False
                break
p.close()
```

Running the above script, we obtain the following result:

```
[+] Opening connection to myspace.satellitesabove.me on port 5016: Done
b'flag{whiskey42551whiskey:GKKCmWMf6GzSsXcWcvtPwVw4gp-N7WsWCljqwPR5Yw7Ea7BAG0CC-JaP9q_n1WDoUPSMdoqUKvAg3Gh53CHTL1M}\n'
[*] Closed connection to myspace.satellitesabove.me port 5016
```
