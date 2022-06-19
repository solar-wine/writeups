# HACK-A-SAT 3: Matters of State

* **Category**: Revenge of the Space Math
* **Points:** 35
* **Solves:** 137
* **Description:**

> I wasn't paying attention in today's Keplerian orbit mechanics class. Who wants to do my homework for me?
>
> note: It will ask you the same question a few time (randomization is busted). Just keep answering and you'll be good.

## Write-up

_Write-up by Solar Wine team_

When connecting to the challenge, a set of [Keplerian elements](https://en.wikipedia.org/wiki/Orbital_elements#Keplerian_elements) are provided. We are tasked to compute satellite's state vector from these elements:

```
$ nc matters_of_state.satellitesabove.me 5300
Ticket please:
ticket{india964294whiskey3:GK1mmXKgpFvuqWpq0tBKn48EIxj4Y4vczJDTr4sldrroibFC8PSmDv9das0cWbof_Q}
Orbital Elements:
Given the following orbit elements:
semi-major axis: 63780.0 km
eccentricity: 0.3
inclination: 63.0 deg
RAAN: 25.0 deg
Mean anomaly: 10.0 deg
Argument of periapsis: 78.0 deg
Time: 2022-01-01T00:00:00.000
Find the state vector of the statellite
Position: X,Y,Z
1,1,1
Velocity: Vx,Vy,Vz
1,1,1
dP: 45231.61015197461 dV: 4.868679595756561
Position incorrect
Velocity incorrect
```

The handy [orbitalpy](https://github.com/RazerM/orbital) Python library has a `KeplerianElements` class which can handle this for us. The only catch is that we have to convert our values to the units that `orbitalpy` expects (meters and radians instead of kilometers and degrees), and then convert the result back before sending it to the server:

```python
import math
from astropy.time import Time
from scipy.constants import kilo
from orbital import earth, KeplerianElements

def convert(a, e, i, raan, m0, arg_pe, epoch):
    """
    :param a: Semi-major axis [km]
    :param e: Eccentricity
    :param i: Inclination [degrees]
    :param raan: Right Ascension of Ascending Node [degrees]
    :param m0: Mean anomaly [degrees]
    :param arg_pe: Argument of periapsis [degrees]
    :param epoch: Reference epoch
    """
    orbit = KeplerianElements(
        a=a * kilo,
        e=e,
        i=math.radians(i),
        raan=math.radians(raan),
        M0=math.radians(m0),
        arg_pe=math.radians(arg_pe),
        ref_epoch=Time(epoch, format="isot", scale="utc"),
        body=earth,
    )
    return [
        (orbit.r.x / kilo, orbit.r.y / kilo, orbit.r.z / kilo),
        (orbit.v.x / kilo, orbit.v.y / kilo, orbit.v.z / kilo),
    ]

pos, vel = convert(
    63780.0, 0.3, 63.0, 25.0, 10.0, 78.0, "2022-01-01T00:00:00.000"
)
print("{},{},{}".format(*pos))
print("{},{},{}".format(*vel))
```

Running the above code would yield the following result:

```
-13816.246763610543,16031.813156003369,39975.9331252851
-3.020297307426827,-1.4932804100621249,-0.15100102642583765
```

All that is left to do is to add a bit of glue to automatically send our values to the server. As was added later in the challenge's description, the server actually always sends the same orbital elements instead of generating random values each time, so we can send our result in a loop until we get the flag:

```python
from pwn import remote

def main(host, port, ticket):
    p = remote(host, port)
    p.recvline()
    p.sendline(ticket)

    while True:
        line = b""
        while line != b"Position: X,Y,Z \n":
            line = p.recvline()
            print(line)

        # Random is broken, the same challenge is always sent by the server
        pos, vel = convert(
            63780.0, 0.3, 63.0, 25.0, 10.0, 78.0, "2022-01-01T00:00:00.000"
        )
        p.sendline("{},{},{}".format(*pos))
        p.sendline("{},{},{}".format(*vel))

if __name__ == "__main__":
    main(
        "matters_of_state.satellitesabove.me",
        "5300",
        "ticket{india964294whiskey3:GK1mmXKgpFvuqWpq0tBKn48EIxj4Y4vczJDTr4sldrroibFC8PSmDv9das0cWbof_Q}",
    )
```
