from skyfield.api import load
from skyfield.framelib import ICRS_to_J2000
import numpy as np

z_vector  = np.array([0, 0, 1])

ts = load.timescale()

junk = load.tle_file("spacejunk.tle")
sats = load.tle_file("sats.tle")

killed = []
for i in range(60, 3600*24, 60):
    if len(killed) == 59: #>= 51:
        break

    t = ts.utc(2021, 6, 26, i // 3600, (i // 60) % 60, i % 60)

    jks_xyz = []
    sats_xyz = []
    for ii, jk in enumerate(junk):
        if ii in killed:
            jks_xyz.append(np.array([0., 0., 0.]))
        else:
            pos = np.dot(ICRS_to_J2000, jk.at(t).position.km)
            jks_xyz.append(pos)
    for sat in sats:
        pos = np.dot(ICRS_to_J2000, sat.at(t).position.km)
        sats_xyz.append(pos)


    for sidx, sat_xyz in enumerate(sats_xyz):
        for jidx, jk_xyz in enumerate(jks_xyz):
            if jidx in killed:
                continue
            target = np.array(jk_xyz - sat_xyz)
            dist = np.linalg.norm(target)
            if dist < 100.:
                target /= dist
                axis = np.cross(z_vector, target)
                axis /= np.linalg.norm(axis)
                arc = np.dot(z_vector, target)

                qr = np.sqrt((1+arc)/2)
                qi = np.sqrt((1-arc)/2)*axis

                print("2021%03d.%02d%02d%02d"%(177 + (i / (24*3600)), (i / 3600) % 24, (i / 60) % 60, i % 60), "SAT" + str(sidx+1), "FIRE", ' '.join([str(x) for x in qi]), qr, dist)
                killed.append(jidx)
                break
"""
53 pieces of space junk have been vaporized! Nice work!
flag{bravo793484oscar2:GMQZwtvSaQe5PvLaLSPftogi513Yex-hl3gE16A-dgnEEWkuMbMES2owZoEGDvJzQLgxRA7RJ1xj_jXOeE_Qmkw}
"""
