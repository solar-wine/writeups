# HACK-A-SAT 2021: Fiddlin' John Carson

* **Category:** Guardians of the...
* **Points:** 22
* **Solves:** 232
* **Description:**

> Where do you come from?

## Write-up

_Write-up by Solar Wine team_

```
         KEPLER        
        CHALLANGE      
       a e i Ω ω υ     
            .  .       
        ,'   ,=,  .    
      ,    /     \  .  
     .    |       | .  
    .      \     / .   
    +        '='  .    
     .          .'     
      .     . '        
         '             
Your spacecraft reports that its Cartesian ICRF position (km) and velocity (km/s) are:
Pos (km):   [8449.401305, 9125.794363, -17.461357]
Vel (km/s): [-1.419072, 6.780149, 0.002865]
Time:       2021-06-26-19:20:00.000-UTC

What is its orbit (expressed as Keplerian elements a, e, i, Ω, ω, and υ)?
```

### Computing the orbital elements

The position and velocity vectors taken together represent the state vector.

In order to obtain the orbital elements from the state vector, we need the standard gravitational parameter of the body around which our object is orbiting. The standard gravitational parameter is simply the product of the mass of the body with the gravitational constant. In the case of earth it is `3.986004418e14 m^3/s^2`.

The state vector is given in ICRF, which is an ECI (Earth-Centered Inertial) frame, so the computing of the orbital elements is straight-forward.

First we need to compute the specific angular moment `h` which is the cross product between the position and velocity:

```python
import numpy as np
r = np.array([8449.401305, 9125.794363, -17.461357])
v = np.array([-1.419072, 6.780149, 0.002865])
h = np.linalg.norm(np.cross(r, v))
```

This gives us `h = 70239.50778173933 km^2/s`.

Next, we need the specific energy E, which is simply the mechanical energy divided by the mass (which is convenient because we don't know the mass of the satellite):

```python
rn = np.linalg.norm(r * 1000) # convert to meters
vn = np.linalg.norm(v * 1000) # convert to meters
earthmu = 3.986004418e14
E = vn**2 / 2 - earthmu / rn
```

This gives us `E = -8058106.232653882 J/kg`.

The first parameter we are asked for is the semi-major axis `a`. It can be obtained using `E`:

```python
a = -earthmu / (2 * E)
akm = a / 1000 # convert to km
```

It gives us `a = 24732.88576072319 km`.

Using the semi-major axis and the specific angular momentum, we can obtain the eccentricity `e`:

```python
hm = h * 1000**2 # convert to m^2/s
e = np.sqrt(1 - (hm)**2 / (a * earthmu))
```

This gives us an eccentricity `e = 0.7068070220620633`.

The inclination can be derived from the specific angular momentum:

```python
hz = np.cross(r, v)[2]
i = np.arccos(hz/h) 
id = i * 180 / np.pi # get it in degrees
```

This gives us `i = 0.11790360842507447 degrees`.

The right ascension of the ascending node, Ω, can also be derived from the specific angular momentum:

```python
hx = np.cross(r, v)[0]
hy = np.cross(r, v)[1]
Omega = np.arctan2(hx, -hy) 
Omegad = Omega * 180 / np.pi # get it in degrees
```

This gives us `Ω = 90.22650379956278 degrees`.

We need to compute the true anomaly whose cosine we know based on the previously obtained values:

```python
nu = np.arccos((a * (1 - e**2) - rn) / (e * rn))
if np.dot(r, v) < 0:
  nu += np.pi
nudg = nu * 180 / np.pi # get it in degrees
```

This gives us `υ = 90.38995503457798 degrees`.

Now we can derive the argument of latitude, which is the sum of the true anomaly and the argument of periapsis:

```python
opn = np.arctan2((r[2] * 1000) / np.sin(i), 1000 * (r[0] * np.cos(Omega) + r[1] * np.sin(Omega)))
opnd = opn * 180 / np.pi
```
Which gives us `ω + υ = -43.02258595754939 degrees`.

Now, simply subtract the true anomaly to the argument of latitude to get the argument of peripasis:

```python
omega = (opn - nu) % (2 * np.pi)
omegad = omega * 180 / np.pi # get it in degrees
```

Finally we get our last element `ω = 226.5874590078726 degrees`.

### Solution

To sum everything up, we know have the Keplerian elements as follows:

```
a = 24732.88576072319 km
e = 0.7068070220620633
i = 0.11790360842507447 degrees
Ω = 90.22650379956278 degrees
ω = 226.5874590078726 degrees
υ = 90.38995503457798 degrees
```

Providing these values to the services, we obtain the following flag:

```
You got it! Here's your flag:
flag{november203917tango2:GPUkYcR0Ig2NeL9YUYvElw4nUgvneNIkRbywFSfyfNBO6fiVujOuhjrpDhoIIRxLkrrNHIbd_iji6pKK5_C5bsI}
```
