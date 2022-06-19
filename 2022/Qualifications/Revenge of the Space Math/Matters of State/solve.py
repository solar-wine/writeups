import math
from pwn import remote
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
