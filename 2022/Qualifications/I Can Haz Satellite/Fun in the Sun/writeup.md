# HACK-A-SAT 3: Fun in the Sun

* **Category**: I Can Haz Satellite
* **Points:** 76
* **Solves:** 55
* **Description:**

We are provided with the TLE of our satellite (SunFunSat) in `sat.tle` and the 
ephemeride DE440 in `de440s.bsp`. The remote service asks for the quaternion to point the solar panels of the SunFunSat to the sun at a precise time:

```
Ticket please:
 ticket{yankee194846zulu3:GLz-8CffBJvumO-CPzi1HE4U-hQMinZDEMLDM6uQ6CQje8mg0vcwLsrfh-ZPFp1DUA}
            FUN
              IN
                THE
                  SUN!!

               y
              /              .
           ////             <O>
          ////o--z           '
            |
            x


Provide the the quaternion (Qx, Qy, Qz, Qw) to point your spacecraft at the sun at 2022-05-21 14:00:00 UTC
The solar panels face the -X axis of the spacecraft body frame or [-1,0,0]
```

The first step was to use `skyfield` to get the position of the satellite 
relative to the solar system's center of mass with `(planets['Earth'] + sat).at(t)` at 2022-05-21 14:00:00 UTC. Then, the `.observe(planets['Sun']).position.au` API gives the astrometric position of the sun relative to the SunFunSat: 

```python
from skyfield.api import EarthSatellite, load

planets = load('de440s.bsp')

ts = load.timescale()
t = ts.utc(2022, 5, 21, 14, 00)

sat = EarthSatellite(
        '1 70003F 22700A   22140.00000000  .00000000  00000-0  00000-0 0  100',
        '2 70003  70.9464 334.7550 0003504   0.0012  16.1023 13.17057395  100',
        'Hack-A-Sat', ts)

print((planets['Earth'] + sat).at(t).observe(planets['Sun']).position.au)
```

This outputs `[0.50290776 0.80585346 0.3493443]`, that can be converted to a quaternion using the same code as in 2021:

```python
import numpy as np

body = [-1, 0, 0]
b = [0.50290776, 0.80585346, 0.3493443]

axis = np.cross(body, b)
axis /= np.linalg.norm(axis)
arc = np.dot(body, b)

qr = np.sqrt((1 + arc) / 2)
qi = np.sqrt((1 - arc) / 2) * axis

print(f'Qx = {qi[0]} Qy = {qi[1]} Qz = {qi[2]} Qw = {qr}')
```

The server accepted these values and gave us the flag:

```
Ticket please:
 ticket{yankee194846zulu3:GLz-8CffBJvumO-CPzi1HE4U-hQMinZDEMLDM6uQ6CQje8mg0vcwLsrfh-ZPFp1DUA}
            FUN
              IN
                THE
                  SUN!!

               y
              /              .
           ////             <O>
          ////o--z           '
            |
            x


Provide the the quaternion (Qx, Qy, Qz, Qw) to point your spacecraft at the sun at 2022-05-21 14:00:00 UTC
The solar panels face the -X axis of the spacecraft body frame or [-1,0,0]
Qx = 0.0
Qy = 0.34478899978532596
Qz = -0.7953454756437823
Qw = 0.4985440000641869
Quaternion normalized to: [ 0.          0.344789   -0.79534548  0.498544  ]
The solar panels are facing 0.395 degrees away from the sun
You got it! Here's your flag:
flag{yankee194846zulu3:GN6v4GSL9Hl9lORAFu8_tedD-aWYrJplfXgGSJcRL9l5muYGX8myZVqWpJfAdBEyawt9rQGCb2FEtTj_4R7kFFA}
```