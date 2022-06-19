import numpy as np
from skyfield.api import EarthSatellite, load

planets = load('de440s.bsp')

ts = load.timescale()
t = ts.utc(2022, 5, 21, 14, 00)

sat = EarthSatellite(
        '1 70003F 22700A   22140.00000000  .00000000  00000-0  00000-0 0  100',
        '2 70003  70.9464 334.7550 0003504   0.0012  16.1023 13.17057395  100',
        'Hack-A-Sat', ts)

pos = (planets['Earth'] + sat).at(t).observe(planets['Sun']).position.au

print(pos)

body = [-1, 0, 0]
b = [0.50290776, 0.80585346, 0.3493443]

axis = np.cross(body, b)
axis /= np.linalg.norm(axis)
arc = np.dot(body, b)

qr = np.sqrt((1 + arc) / 2)
qi = np.sqrt((1 - arc) / 2) * axis

print(f'Qx = {qi[0]} Qy = {qi[1]} Qz = {qi[2]} Qw = {qr}')
