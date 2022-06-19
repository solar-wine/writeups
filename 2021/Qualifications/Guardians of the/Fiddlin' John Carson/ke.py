import numpy as np

r = np.array([8449.401305, 9125.794363, -17.461357])
v = np.array([-1.419072, 6.780149, 0.002865])
h = np.linalg.norm(np.cross(r, v))

rn = np.linalg.norm(r * 1000) # convert to meters
vn = np.linalg.norm(v * 1000) # convert to meters
earthmu = 3.986004418e14
E = vn**2 / 2 - earthmu / rn

a = -earthmu / (2 * E)
akm = a / 1000 # convert to km

hm = h * 1000**2 # convert to m^2/s
e = np.sqrt(1 - (hm)**2 / (a * earthmu))

hz = np.cross(r, v)[2]
i = np.arccos(hz/h) 
idg = i * 180 / np.pi # get it in degrees

hx = np.cross(r, v)[0]
hy = np.cross(r, v)[1]
Omega = np.arctan2(hx, -hy) 
Omegadg = Omega * 180 / np.pi # get it in degrees

nu = np.arccos((a * (1 - e**2) - rn) / (e * rn))
if np.dot(r, v) < 0:
  nu += np.pi
nudg = nu * 180 / np.pi # get it in degrees

opn = np.arctan2((r[2] * 1000) / np.sin(i), 1000 * (r[0] * np.cos(Omega) + r[1] * np.sin(Omega)))
opndg = opn * 180 / np.pi

omega = (opn - nu) % (2 * np.pi)
omegadg = omega * 180 / np.pi # get it in degrees

print(akm)
print(e)
print(idg)
print(Omegadg)
print(omegadg)
print(nudg)
