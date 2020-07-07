# Where's the Sat? 

* **Category:** Space and Things
* **Points:** 43 points 
* **Solves:** 107
* **Description:**

> Let's start with an easy one, I tell you where I'm looking at a satellite, you 
> tell me where to look for it later.
>
> You'll need these files to solve the challenge.
> <https://static.2020.hackasat.com/320e0c77c598c8e358442b597b1733e2b88656c9/stations.zip>
>
> Connect to the challenge on `where.satellitesabove.me:5021`. Using netcat, you 
> might run `nc where.satellitesabove.me 5021`

## Write-up

_Write-up by Solar Wine team_

The challenge archive contains a bunch of satellites TLEs:

```
ISS (ZARYA)             
1 25544U 98067A   20101.49789620 -.00000843  00000-0 -72437-5 0  9994
2 25544  51.6442 323.4418 0003567  97.5001 333.2274 15.48679651221520
NSIGHT                  
1 42726U 98067MF  20101.41972867  .00345433  66479-4  45399-3 0  9990
2 42726  51.6243 209.0044 0009087 327.3341  32.7108 16.06219602164768
KESTREL EYE IIM (KE2M)  
1 42982U 98067NE  20101.36603301  .00013519  00000-0  12255-3 0  9998
2 42982  51.6346 268.5674 0003561 191.4761 168.6155 15.68377454140382
ASTERIA                 
1 43020U 98067NH  20100.83214555  .00396983  83692-4  55667-3 0  9997
2 43020  51.6446 225.1325 0006274 348.4396  11.6471 16.05206331136684
DELLINGR (RBLE)         
1 43021U 98067NJ  20101.44979837  .00014318  00000-0  12632-3 0  9999
2 43021  51.6355 266.9432 0001692 163.0588 197.0466 15.68988885136186
...
```

Connecting to the service gives us an initial date and position and then prompts us 
for satellite's position at a future date:

```
$ nc where.satellitesabove.me 5021
Ticket please:
ticket{golf5112whiskey:GI-kHtwKXvPOj8WtdLAs0iavjjBh9w0ype8qIHhB9pG5vPKdsU9MrNfSCchexrpxaw}
Please use the following time to find the correct satellite:(2020, 3, 18, 4, 39, 14.0)
Please use the following Earth Centered Inertial reference frame coordinates to find the satellite:[-1255.045343229649, -6601.796354622012, -939.4055314195194]
Current attempt:1
What is the X coordinate at the time of:(2020, 3, 18, 7, 33, 46.0)?
-3829.31063902
```

The whole tasks can be summarized in steps:

  - Which satellite is exactly at -1255.045343229649 -6601.796354622012 -939.4055314195194 the 2020-3-18 at 4:39:14?
  - Where will this satellite be located the 2020-3-18 at 7:33:46?

As the parameters are always the same and we were not expecting to have to answer 
too much times, the following script was written:

```python
from datetime import datetime

from skyfield.api import EarthSatellite, load, utc
from itertools import islice

THRESHOLD = 1e-4

ts = load.timescale()

initial_time = datetime(2020, 3, 18, 4, 39, 14).replace(tzinfo=utc)
next_time = datetime(2020, 3, 18, 7, 33, 46).replace(tzinfo=utc)
initial_pos = [-1255.045343229649, -6601.796354622012, -939.4055314195194]

with open('stations.txt', 'r') as tles:
	while 1:
		tle_string =  [x.strip() for x in islice(tles, 3)]
		ts = load.timescale()
		sat = EarthSatellite(tle_string[1], tle_string[2], tle_string[0], ts)
		geocentric_pos = sat.at(ts.utc(initial_time))
		if all([abs(geocentric_pos.position.km[i] - initial_pos[i]) < THRESHOLD for i in range(0, 3)]):
			print(f'Identified satellite: {sat}')
			break

print(sat.at(ts.utc(next_time)).position.km)
```

The reasoning is fairly simple here, it is only an implementation of the two steps 
described above using Skyfield's API. It was executed and the variable `next_time` 
modified at each attempt to answer the three rounds of questions:

```
$ nc where.satellitesabove.me 5021
Ticket please:
ticket{golf5112whiskey:GI-kHtwKXvPOj8WtdLAs0iavjjBh9w0ype8qIHhB9pG5vPKdsU9MrNfSCchexrpxaw}
Please use the following time to find the correct satellite:(2020, 3, 18, 4, 39, 14.0)
Please use the following Earth Centered Inertial reference frame coordinates to find the satellite:[-1255.045343229649, -6601.796354622012, -939.4055314195194]

Current attempt:1
What is the X coordinate at the time of:(2020, 3, 18, 7, 33, 46.0)?
-3829.31063902
What is the Y coordinate at the time of:(2020, 3, 18, 7, 33, 46.0)?
-4877.25452829
The Y coordinate for (2020, 3, 18, 7, 33, 46.0) is correct!
What is the Z coordinate at the time of:(2020, 3, 18, 7, 33, 46.0)?
2744.16916282
The Z axis coordinate for (2020, 3, 18, 7, 33, 46.0) is correct!

Current attempt:2
What is the X coordinate at the time of:(2020, 3, 18, 6, 51, 10.0)?
3121.08726981
What is the Y coordinate at the time of:(2020, 3, 18, 6, 51, 10.0)?
5817.54864777
The Y coordinate for (2020, 3, 18, 6, 51, 10.0) is correct!
What is the Z coordinate at the time of:(2020, 3, 18, 6, 51, 10.0)?
-1547.88157169
The Z axis coordinate for (2020, 3, 18, 6, 51, 10.0) is correct!

Current attempt:3
What is the X coordinate at the time of:(2020, 3, 18, 3, 49, 6.0)?
2315.80630935
What is the Y coordinate at the time of:(2020, 3, 18, 3, 49, 6.0)?
6355.29320148
The Y coordinate for (2020, 3, 18, 3, 49, 6.0) is correct!
What is the Z coordinate at the time of:(2020, 3, 18, 3, 49, 6.0)?
-463.40452801
The Z axis coordinate for (2020, 3, 18, 3, 49, 6.0) is correct!

flag{golf5112whiskey:GHRHt_DEIn15TK1ViYho6Z3MOpLye92LncFhv7MdxAEe7rx_RwNSLzqrUfWhk7KmhqGO_kKZHtfM_hhgYmxSWUI}
```
