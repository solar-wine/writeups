# SPACE SECURITY CHALLENGE 2020 HACK-A-SAT: Attitude Adjustment

* **Category:** Astronomy, Astrophysics, Astrometry, Astrodynamics, AAAA
* **Points:** 69
* **Solves:** 62
* **Description:**

> attitude.satellitesabove.me:5012
>
> [Download](https://generated.2020.hackasat.com/attitude/attitude-tango9297uniform.tar.bz2)
>
> Our star tracker has collected a set of boresight reference vectors, and identified which stars in the catalog they correspond to. Compare the included catalog and the identified boresight vectors to determine what our current attitude is.
> 
> Note: The catalog format is unit vector (X,Y,Z) in a celestial reference frame and the magnitude (relative brightness)

## Write-up

_Write-up by Solar Wine team_


The tarball contains a single file, `test.txt`, which is a catalog of stars in (X, Y, Z, Magnitude) format.

In order to quickly use it in a `Python` script, a conversion is first made to have it as a matrix:

```console
$ (echo -n catalog = [; sed '/^$/d;s/^/[/;s/$/],/' test.txt ; echo ']') > has_catalog.py
```

When connecting to the service, we get the following message:

```
nc attitude.satellitesabove.me 5012
Ticket please:
ticket{tango9297uniform:GE8_T6AtnptFxP2SoK4AKaBxjWFbAoIs9QZ2zJo-2kA4fM-EdBgMAVI0zV1NnjkSzg} 
  ID : X,               Y,              Z
--------------------------------------------------
 170 : -0.132011,       0.180227,       0.974726
 211 : -0.202745,       0.291574,       0.934815
 327 : -0.300356,       0.207050,       0.931084
 353 : -0.292654,       0.401459,       0.867862
 452 : -0.306250,       0.421067,       0.853764
 500 : -0.147145,       0.438931,       0.886391
 751 : -0.159962,       0.188857,       0.968889
 968 : -0.214655,       0.290742,       0.932412
1494 : -0.170883,       0.198249,       0.965141
1501 : -0.035225,       0.312275,       0.949338
1559 : -0.110399,       0.451429,       0.885451
1561 : -0.215373,       0.309577,       0.926162
1564 : -0.036229,       0.366068,       0.929882
1598 : -0.224690,       0.318612,       0.920869
1692 : -0.072827,       0.360695,       0.929836
1736 : -0.122894,       0.413891,       0.901993
1981 : -0.137940,       0.167115,       0.976240

TEST
Format error: Give your answer as '%f,%f,%f,%f
Failed...
```

Since the format is four floats, the expected result for the attitude is a [Quaternion](https://en.wikipedia.org/wiki/Quaternions_and_spatial_rotation).

A naive approach to compute the rotation matrix could be to:

  - compute the rotation matrix between the catalog coordinate for the first star with the corresponding measured coordinate (using cross, dot, norm and skew matrix)
  - compute the average angle along the axis defined by the vector from the previously given star to align the other catalog stars with their corresponding measured stars
  - compute the rotation matrix corresponding to the axis and angle previously obtained
  - multiply the second rotation matrix with the first rotation matrix
  - convert the result to a quaternion

While this method works for several rounds of the challenge, it is not accurate enough to get the flag.

The computation of the **optimal** rotation matrix that minimizes the root mean square deviation is actually a solved problem using the [Kabsch algorithm](https://en.wikipedia.org/wiki/Kabsch_algorithm).

The package `rmsd` available in `Python` implements this algorithm.

After a translation so that both centroids for the given stars coincide with the origin of the coordinate system, the optimal rotation matrix can be obtained using the `kabsh()` method.

Finally, using `scipy`'s `Rotation` sub-module, the matrix is converted to a quaternion and sent back to the server.

The following implementation has been used to solve the challenge:

```python
#!/usr/bin/env python3

import numpy as np
from scipy.spatial.transform import Rotation
import pwn
import rmsd
from has_catalog import *

TICKET = b"ticket{tango9297uniform:GE8_T6AtnptFxP2SoK4AKaBxjWFbAoIs9QZ2zJo-2kA4fM-EdBgMAVI0zV1NnjkSzg}"
lines = []

def ticket():
    p.recvuntil(b'Ticket please')
    p.sendline(TICKET)

def nextr():
    rez = p.recvuntil(b'\n\n').split(b'\n')
    lines = []
    for line in rez:
        if b"0." in line:
            id = int(line.split(b' : ')[0].strip())
            r = line.split(b' : ')[1].split(b',\t')
            x = float(r[0])
            y = float(r[1])
            z = float(r[2])
            lines.append([id, x, y, z])
    return lines

def compute_matrix(stars):
    v_ref, v_obs = [], []
    for idx, x, y, z in stars:
        v_ref.append([catalog[idx][0], catalog[idx][1], catalog[idx][2]])
        v_obs.append([x, y, z])

    A = np.array(v_ref)
    B = np.array(v_obs)

    A -= rmsd.centroid(A)
    B -= rmsd.centroid(B)

    R = rmsd.kabsch(A, B)

    sol_dcm = Rotation.from_dcm(R)
    sol = sol_dcm.as_quat()

    return ','.join(str(x) for x in sol)

p = pwn.remote('attitude.satellitesabove.me',5012)
ticket()

running = True
while running:
    stars = nextr()

    sol = compute_matrix(stars)

    p.sendline(sol)
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
[+] Opening connection to attitude.satellitesabove.me on port 5012: Done
b'flag{tango9297uniform:GJA_xK6dslrSian6wSaAMDcWkyhpDBXlzLq6D3wSltrVMloNRSwsTM4T-qTXgcorGmw8tGP1-mcnp1dtUI_SLA0}\n'
[*] Closed connection to attitude.satellitesabove.me port 5012
```

