# HACK-A-SAT 2021: Take Out the Trash

* **Category:** Deck 36, Main Engineering
* **Points:** 142
* **Solves:** 24
* **Description:**

> A cloud of space junk is in your constellation's orbital plane. Use the space lasers on your satellites to vaporize it! Destroy at least 51 pieces of space junk to get the flag.
> 
> The lasers have a range of 100 km and must be provided range and attitude to lock onto the space junk. Don't allow any space junk to approach closer than 10 km.
> 
> Command format:
> 
> ```
> [Time_UTC] [Sat_ID] FIRE [Qx] [Qy] [Qz] [Qw] [Range_km]
> ```
> 
> Command example:
> 
> 2021177.014500 SAT1 FIRE -0.7993071278793108 0.2569145028089314 0.0 0.5432338847750264 47.85760531563315
> 
> This command fires the laser from Sat1 on June 26, 2021 (day 177 of the year) at 01:45:00 UTC and expects the target to be approximately 48 km away. The direction would be a [0,0,1] vector in the J2000 frame rotated by the provided quaternion [-0.7993071278793108 0.2569145028089314 0.0 0.5432338847750264] in the form [Qx Qy Qz Qw].
> 
> One successful laser command is provided for you (note: there are many possible combinations of time, attitude, range, and spacecraft to destroy the same piece of space junk):
> 
> 2021177.002200 SAT1 FIRE -0.6254112512084177 -0.10281341941423379 0.0 0.773492189779751 84.9530354564239

## Write-up

_Write-up by Solar Wine team_

```
A cloud of space junk is in your constellation's orbital plane.
Use the lasers on your satellites to vaporize it!
The lasers have a range of 100km. Don't allow any space junk to approach closer than 30km.
Use the provided TLEs for your spacecraft and the space junk. Provide commands in the following format:
[Time_UTC] [Sat_ID] FIRE [Qx] [Qy] [Qz] [Qw] [Range_km]

Provide command sequences:
```

### Simulating trajectories

Two files are provided for this challenge: `sats.tle` and `spacejunk.tle`.

There is one set of TLE describing 15 satellites and one set of TLE describing 59 pieces of space junk.

In order to solve this challenge, we need to simulate the trajectory of all these objects, detect when a piece of space junk is closer than 100km of a satellite so we can fire at it, remove the space junk from our list of objects, then continue the simulation.

We chose a time resolution of 1 minute for our simulation so that we can ensure no space junk is going to come closer than 10km to our satellites considering the velocities involved.

### Getting the right coordinates

Because the rotation quaternion are relative to the J2000 frame, we need to compute the objects coordinates in J2000. Since December 2020, [`Skyfield`](https://rhodesmill.org/skyfield/) supports conversion to J2000. This is really handy since `Skyfield`'s API is relatively easy to use for tracking objects in the sky.

While the `frame_xyz()` is supposed to do that conversion for us, it doesn't actually work. Since TLE are in the TEME frame, applying a GCRS to J2000 rotation matrix won't do the trick. To fix this, we can directly import the `ICRS_to_J2000` matrix and apply the dot product ourselves.

### Generating the commands

Now that we have a working simulation that gives us coordinates in the correct frame, we need to generate the list of commands to specify the time and rotation quaternion for a given satellite to destroy some space junk.

Our strategy is as follows:

* Keep a tab of the destroyed pieces of space junk so as to not try to destroy inexistent space junk
* Update the coordinates of all live objects every minute
* For each satellite, select the closest space junk whose distance is less than 100km
* For all satellites in position to fire, compute the rotation quaternion as described in the _Quaternion_ write-up
* Format the command as asked in the problem description

After fixing some bugs introduced because of some lack of sleep, we could finally generate the list of commands over a 24 hour period.

### Simulation code

This version of the code uses a simpler approach to do the coordinate conversion compared to what was used during the qualifications. Because we used a trial-and-error approach for the conversion, the original code ended up a little bit ugly, so here is a cleaned up version:

```python
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
```

### Solution

Running the above code generates this list of commands. However, we couldn't get the flag. Apparently, this challenge was too overloaded to be able to run the contestant commands before its configured timeout.

```text
2021177.002100 SAT1 FIRE -0.6307652171897559 -0.1205753440284496 0.0 0.7665486463336696 98.45315622551468
2021177.002300 SAT1 FIRE -0.588434006249713 -0.07577558587248488 0.0 0.8049866339726358 73.79197663512022
2021177.002500 SAT1 FIRE -0.4461516614397337 -0.3345826606053656 0.0 0.8300621291305851 53.27933948562646
2021177.002700 SAT1 FIRE 0.008444842814030651 -0.47860595570874426 0.0 0.877989193435754 90.91150270081964
2021177.002900 SAT1 FIRE 0.03271264895895779 -0.39469282189525046 0.0 0.9182306131590539 57.87682446119459
2021177.003100 SAT1 FIRE 0.6039604914182247 -0.05172919355049064 0.0 0.7953337760591288 39.35637000018447
2021177.003300 SAT1 FIRE 0.6551315635558657 0.1729189562557695 0.0 0.735460174992679 52.33514447550101
2021177.003500 SAT1 FIRE 0.582544067547296 -0.1601632484601636 0.0 0.7968626878001875 96.41975269801438
2021177.003700 SAT1 FIRE 0.44634261962377186 0.5707206369974221 0.0 0.6892432229718662 95.43001138827456
2021177.003900 SAT1 FIRE 0.5782869892880369 0.3658058595180267 0.0 0.7292257751632588 87.34019479076558
2021177.010500 SAT1 FIRE 0.7048452105278431 0.428434379202454 0.0 0.5653646716176812 98.47148469590735
2021177.010900 SAT1 FIRE 0.6286628372633042 0.5359342596928104 0.0 0.5635224097864889 96.18650873400088
2021177.011100 SAT1 FIRE 0.6050382495225859 0.6095860528515288 0.0 0.5121850844992836 91.54600288898449
2021177.011300 SAT1 FIRE 0.6124183973269752 0.5637905778432898 0.0 0.5541515054121828 83.90330721977502
2021177.011500 SAT1 FIRE 0.5594426020313661 0.6050080406400522 0.0 0.5665591282410509 79.18653685495447
2021177.011700 SAT1 FIRE 0.3637907007290732 0.7153126538141874 0.0 0.5966440591813132 99.84934039944689
2021177.011900 SAT1 FIRE 0.4531585450607392 0.6693985587137631 0.0 0.5886874405237219 97.13564437357444
2021177.012100 SAT1 FIRE 0.630192224073907 0.48159399382290347 0.0 0.6090361120906443 74.72698508020892
2021177.012500 SAT1 FIRE 0.10452364677106883 0.7897532693509257 0.0 0.6044539526011896 97.28314628913405
2021177.012700 SAT1 FIRE 0.003023563075745998 0.8113421203744334 0.0 0.5845637875994761 90.39904529338875
2021177.012900 SAT1 FIRE 0.12739918137943623 0.7809679372653834 0.0 0.6114397186536885 99.6625570508129
2021177.013100 SAT1 FIRE -0.0007207350963059027 0.8001789328523385 0.0 0.5997609156657455 97.18051305199423
2021177.013300 SAT1 FIRE 0.1611632999656829 0.7726947593874348 0.0 0.6139781751490565 90.0578076894387
2021177.013500 SAT1 FIRE -0.17558104202919822 0.7740370073727364 0.0 0.6083074953486924 63.802571148976945
2021177.015700 SAT2 FIRE -0.6752603713321275 -0.17549353686713265 0.0 0.716397549846635 83.25769646098401
2021177.015900 SAT2 FIRE -0.32673023487531855 -0.4350311477631028 0.0 0.8390442503791063 91.19289284269317
2021177.020100 SAT2 FIRE 0.007419500014359158 -0.6027195130098875 0.0 0.7979186297215155 80.43361213992392
2021177.020300 SAT2 FIRE 0.01710999387767167 -0.5122698469942426 0.0 0.8586540933169778 98.92483176706037
2021177.020500 SAT2 FIRE 0.3798185470720492 -0.4441883074926456 0.0 0.8114398429870795 73.59872080106821
2021177.020700 SAT2 FIRE 0.2889072265895513 -0.5100334258095899 0.0 0.8101842500204921 89.18550611323275
2021177.020900 SAT2 FIRE -0.031043405889259447 0.7784302579171213 0.0 0.626963029619673 58.99264567911053
2021177.021100 SAT2 FIRE 0.13208058935112002 0.7161483413616718 0.0 0.6853366115140699 61.930491309409845
2021177.021300 SAT2 FIRE -0.06561729773931596 0.7588718425318124 0.0 0.6479258420913323 99.83559648248797
2021177.021500 SAT2 FIRE 0.534198416102906 -0.29387067228300484 0.0 0.7926361587797276 97.43634174178294
2021177.021700 SAT2 FIRE 0.11664325771852545 0.7599565318595561 0.0 0.6394219421577625 92.93897474338324
2021177.021900 SAT2 FIRE 0.6612500812169668 0.029775150093287444 0.0 0.7495743929240626 38.65230430801609
2021177.023900 SAT1 FIRE -0.4373876577664783 -0.5499910727015054 0.0 0.7114786411286016 84.54274532768306
2021177.025300 SAT2 FIRE 0.3436062468957419 0.7423931365805017 0.0 0.5751410069299414 99.91975531460179
2021177.025500 SAT2 FIRE 0.3657066466505712 0.6939923520389759 0.0 0.6201880875242642 92.26088625372832
2021177.030300 SAT2 FIRE 0.09634417279033944 0.8035665292073692 0.0 0.5873658429862666 98.08125463876809
2021177.033100 SAT3 FIRE 0.721595216751225 -0.07898262129430214 0.0 -0.6877950920842876 88.54239925862193
2021177.033300 SAT3 FIRE -0.6017702852378233 0.2780455248285494 0.0 0.7487076932472414 80.34156946351614
2021177.033500 SAT3 FIRE -0.0360659185911643 -0.5153934962502683 0.0 0.8561943666826477 93.34347521629337
2021177.033700 SAT3 FIRE 0.20247565077532778 -0.544022483324282 0.0 0.814274614906291 79.9572881682789
2021177.033900 SAT3 FIRE 0.2832963540226628 0.2165568983705819 0.0 0.934262428638538 19.905964032973998
2021177.034100 SAT3 FIRE -0.3655720511968443 0.675254208621344 0.0 0.6406159763250479 98.39566312954327
2021177.041900 SAT3 FIRE 0.5017378080496979 0.6435116133214781 0.0 0.5780587993395417 97.90771227786868
2021177.100100 SAT7 FIRE 0.4064199879065285 -0.4243240290592206 0.0 0.8091797771774867 99.31384608498823
2021177.103100 SAT6 FIRE -0.26820616353891574 -0.5545868652137866 0.0 0.7877175018825479 92.30196571580689
2021177.113300 SAT8 FIRE 0.23706923480408582 -0.5733943021241956 0.0 0.7842302928355369 94.94314345385624
2021177.120900 SAT7 FIRE 0.005388738627390378 -0.6109260051748201 0.0 0.7916693613479944 99.55831512123827
2021177.130700 SAT9 FIRE 0.22034882614277915 -0.5590178923638777 0.0 0.7993405975143183 92.52305252580292
```

Fortunately, we didn't give up, and finally obtained the flag:

```
52 pieces of space junk have been vaporized! Nice work!
flag{bravo793484oscar2:GMQZwtvSaQe5PvLaLSPftogi513Yex-hl3gE16A-dgnEEWkuMbMES2owZoEGDvJzQLgxRA7RJ1xj_jXOeE_Qmkw}
```
