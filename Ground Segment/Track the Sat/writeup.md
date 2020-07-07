# Track the sat

* **Category:** Ground Segment
* **Points:** 44 points 
* **Solves:** 106
* **Description:**

> You're in charge of controlling our hobbyist antenna. The antenna is controlled 
> by two servos, one for azimuth and the other for elevation. Included is an example 
> file from a previous control pattern. Track the satellite requested so we can see 
> what it is broadcasting
>  
> Connect to the challenge on `trackthesat.satellitesabove.me:5031`. Using netcat, 
> you might run `nc trackthesat.satellitesabove.me 5031`. 
>  
> You'll need these files to solve the challenge.
> <https://static.2020.hackasat.com/b05745a1feed6b27afbad7454e9d328d4d00405a/examples.tar.gz>

## Write-up

_Write-up by Solar Wine team_

Upon connection to the challenge, we are granted with the following parameters:

```
$ nc trackthesat.satellitesabove.me 5031
Ticket please:
ticket{charlie28117november:GH1m813XiC8_Cxc8IDRaI9W3_ZPKOTSIZMV_Z7cmH-cre2RsatAi4Plx39shKvKhow}
Track-a-sat control system
Latitude: 4.3666
Longitude: 18.5583
Satellite: APRIZESAT 3
Start time GMT: 1586288893.506685
720 observations, one every 1 second
Waiting for your solution followed by a blank line...
```

Also, the archive contains: 

  - `README.txt`: general information about the challenge, the most important part
  is `the motors accept duty cycles between 2457 and 7372, from 0 to 180 degrees.`
  - `challenge[0-4].txt`, `solution[0-4].txt`: 5 examples of resolution
  - `active.txt`: TLEs in use in the ground station

Using these parameters, it is easy to calculate satellite's position using a library
like _SkyField_ or _astropy_. No need to fire up _pwntools_, as the challenge is 
unique per team and fixed.

As the challenges are only simulations and have to be reproducible the day of the
event, players were not expected to look for the actual TLE of `APRIZESAT 3` 
online. The associated parameters can be found in `active.txt`:

```
APRIZESAT 3             
1 35686U 09041F   20101.11595516  .00000055  00000-0  12743-4 0  9990
2 35686  98.1908 155.9328 0071502 270.9995  88.3028 14.87374861579979
```

We then used [`astropy.coordinates.EarthLocation`](https://docs.astropy.org/en/stable/api/astropy.coordinates.EarthLocation.html) 
to transform the geodetic coordinates (latitude / longitude) to geocentric coordinates 
(X / Y / Z), and [`pycraf.satellite.SatelliteObserver`](https://bwinkel.github.io/pycraf/api/pycraf.satellite.SatelliteObserver.html)
to calculate of position of the satellite relative to our location on Earth, not
to the Earth itself! Hence, the result of this calculus will be two angles called
azimuth and elevation.

The last step was to "convert" these two values in duty cycles for the motors.
As described in `README.txt`, an angle of 0° is represented by 2457 and 180°
by 7372. The antenna will then move of `(7372 - 2457) / 180 = 27.31`
cycle / degree. Quickly account for negative angle values, _et voilà!_

```python
from datetime import datetime, timezone
from astropy.time import Time
from astropy.coordinates import EarthLocation
from pycraf import satellite

APRIZESAT_TLE = '''APRIZESAT 3             
1 35686U 09041F   20101.11595516  .00000055  00000-0  12743-4 0  9990
2 35686  98.1908 155.9328 0071502 270.9995  88.3028 14.87374861579979'''

def to_duty_cycles(az, el):
  duty_coef = (7372 - 2457) / 180
  if az > 0 and el > 0:
      az = (az * duty_coef) + 2457
      el = (el * duty_coef) + 2457
  elif az < 0 and el > 0 :
      az = 7372 + (az*duty_coef)
      el = 7372 - (el*duty_coef)
  elif az > 0 and el < 0:
      az = 7372 - (az*duty_coef)
      el = 7372 + (el*duty_coef)
  elif az < 0 and el < 0:
      az = 7372 + (az*duty_coef)
      el = 7372 + (el*duty_coef)

  return (int(az), int(el))

# Don't swap latitude and longitude 0:-)
location = EarthLocation.from_geodetic(18.5583, 4.3666)
sat_obs = satellite.SatelliteObserver(location)

for i in range(0, 720):
    dt = datetime.fromtimestamp(1586288893.506685 + i, tz=timezone.utc)
    t = Time(dt)
    az, el, _ = sat_obs.azel_from_sat(APRIZESAT_TLE, t)

    az, el =  to_duty_cycles(az.value, el.value)
    print(f"{dt.timestamp()}, {az}, {el}")
```

Notice the use of `datetime.fromtimestamp(..., tz=timezone.utc)`, as calculations
have to be performed on UTC and `datetime.fromtimestamp()` silently converts
the result of `datetime.fromtimestamp()` to your machine's timezone.

Submitting the 720 observations and getting the flag is only a copy-paste away:

```
$ nc trackthesat.satellitesabove.me 5031
Ticket please:
ticket{charlie28117november:GH1m813XiC8_Cxc8IDRaI9W3_ZPKOTSIZMV_Z7cmH-cre2RsatAi4Plx39shKvKhow}
Track-a-sat control system
Latitude: 4.3666
Longitude: 18.5583
Satellite: APRIZESAT 3
Start time GMT: 1586288893.506685
720 observations, one every 1 second
Waiting for your solution followed by a blank line...

1586288893.506685, 7096, 2466
1586288894.506685, 7096, 2468
1586288895.506685, 7096, 2470
1586288896.506685, 7097, 2472
1586288897.506685, 7097, 2473
1586288898.506685, 7097, 2475
1586288899.506685, 7097, 2477
1586288900.506685, 7097, 2479
[...]
1586289604.506685, 7001, 7284
1586289605.506685, 7001, 7286
1586289606.506685, 7001, 7288
1586289607.506685, 7001, 7290
1586289608.506685, 7002, 7292
1586289609.506685, 7002, 7294
1586289610.506685, 7002, 7295
1586289611.506685, 7002, 7297
1586289612.506685, 7002, 7299

Congratulations: flag{charlie28117november:GMPLvXr4V0vSCVXXvyl5wzgnyQHoUXs5DcruL7x6RV6ncPMTDNqSlYVze8Uy9b2SZhraDJgUFv9J0lg-k8AGxo8}
```
