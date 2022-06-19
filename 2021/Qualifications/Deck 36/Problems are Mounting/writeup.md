# HACK-A-SAT 2021: Problems are Mounting

* **Category:** Deck 36, Main Engineering
* **Points:** 134
* **Solves:** 26
* **Description:**

> A cubesat has 6 solar sensors, one on each side of the satellite. At any given time, the sun can be observed by a maximum of 3 sensors at a time. The combination of measurements from 3 sensors provides the sun vector in the spacecraft coordinate system.
>
> The spacecraft coordinate system is a Cartesian system with the origin at the center of the satellite. The sun vector, in combination with other observations such as the Earth magnetic field vector can be used to determine the full 3D attitude of the spacecraft.
>
> During launch, the mounting angle of one of the sun sensors shifted and is no longer aligned with the spacecraft coordinate system's axis causing the sun vector determination to be wrong.
>
> Determine which of the 6 sensors was shifted and find it's vector norm in order to make corrections to the attitude determination. To get the flag, find the correct vector norm of the shifted solar sensor.
>
> Given information:
>
> * 6 solar sensors on a CubeSat, one on each face. In spacecraft coordinates the vector norms should be (1,0,0), (0,1,0), (0,0,1), (-1,0,0), (0,-1,0), (0,0,-1).
> * One of the sensors shifted and is no longer aligned with the axis of the satellite.
> * Assume the satellite is always 1 A.U. (Astronomical Unit) distance from the sun).
> * Each solar sensor has a 1 square cm area and a 10% efficiency. A 10 ohm resistor is used as a voltmeter.


## Write-up

_Write-up by Solar Wine team_

```
      |
    \ | /
     \*/
  --**O**--
     /*\           PROBLEMS ARE MOUNTING
    / | \
      |


               __                                     __
              |\ \            ___________,           |\ \
              | \ \          |`           \          | \ \
              |  \ \         | `           \         |  \ \
              |   | |_________  `           \________|  | |
              |   | |__________) +-----------+________) | |
              |   | |        |   :           :       |  | |
              |   | |        |   :           :       |  | |
              |   | |        `   :           :       |  | |
              |   | |         `  :           :       |  | |
               \  | |          ` :           :        \ | |
                \ | |           `:___________>         \| |
                  --                                    --
```

### Maximum expected measured voltage

The online service starts by asking a preliminary question:

```
First things first, what is the expected magnitude of measured voltage on the
sun sensor? Assume the sun sensor has 10% efficiency, is 1 AU from the sun, has
an area of 1 cm, and a 10 ohm resistor as a voltmeter.
```

The result can be obtain in three small steps:

* Find out the amount of energy per unit of surface received from the Sun at the given distance.
* Deduce the amount of energy received by the sensor.
* Compute the measured voltage.

As the CubeSat is assumed to be 1 astronomical unit away from the Sun (i.e. the distance from Earth to the Sun), the first value does not have to be computed: we can directly use the [solar constant](https://en.wikipedia.org/wiki/Solar_constant) which has an approximate value of 1.3608 kW/m².

The amount of energy received by the sensor is thus simply the solar constant multiplied by the surface of the sensor (1 cm² = 0.0001 m²). Multiplying this by the sensor's efficiency gives us the output from the sensor, from which we can compute the measure voltage using [Ohm's law](https://en.wikipedia.org/wiki/Ohm's_law).

Here is a Python script computing the result:

```python
import math

def estimate_voltage():
    H0 = 1360.8  # W/m^2

    S = 10**-4  # m (= 1cm^2)
    Pr = H0 * S

    e = 0.1  # 10%
    P = e * Pr

    R = 10  # Ohm
    return math.sqrt(P * R)
```

We obtain `0.3688902275745456` from this code, which the server accepts as a valid solution:

```
(Format answers as a single float): 0.3688902275745456
Good, we're on the same page! Moving on...
```

### Shifted sensor vector norm

After answering the previous question, the real challenge starts:

```
Here are the initial voltages of the 6 sensors:
<+X-Axis:0.044396441664211035
+Y-Axis:0.30462677628495133
+Z-Axis:0.3420103887239637
-X-Axis:0
-Y-Axis:0
-Z-Axis:0
>OK let's figure out what's wrong
Specify a rotation to apply to the satellite for the next measurements.
All units are in degrees
(Format answers as euler angles in the form "r:X,Y',Z''"):
Rotations are not cummulative, each rotation originates from the initial postion
You may also submit a rotation matrix directly
Format the rotation matrix as "r:i11,i12,i13,i21,i22,i23,i31,i32,i33"
Where ijk represents element i in the jth row and the kth column.
At any point, you can submit your final answer in form: "s:X,Y,Z"
The final answer should be a unit vector
```

**Note:** The shifted sensor, the value of the shift, and the satellite's original orientation changed at each run.

Here is the plan we came up with in the end:

1. Determine which sensor is shifted. If it is not the sensor on the `+X` axis, restart.
2. Find the rotation for which the `+X` sensor measures the maximum voltage (which should approximately match the value computed in the first part).
3. Find the rotation for which the `-X` sensor measures the maximum voltage.
4. Find the `+X` sensor's vector based on the measure angle difference with the `-X` sensor which has a known vector.

It should be noted that this plan was not clear from the start; multiple members of the team explored different directions to maximize our chances of solving the challenge. For the sake of clarity and brevity, not all the options studied will be described here.

Here is a simplified view of the problem, with the shifted sensor pointing towards the sun:

![3D view of a CubeSat mounted with sensors facing the Sun](images/cubesat.png)

#### Finding out which sensor is shifted

From the challenge's description and banner, we know that:

* Sensors are each placed on one of the satellite's faces and were originally *aligned with the satellite's axis*.
* Only one sensor is shifted.
* We can easily rotate the satellite alongside any of its axes.

This means that, for example, if we rotate the satellite around its `X` axis, then sensors `+X` and `-X` should keep measuring the same output, regardless of the angle. Same goes for sensors `+Y` and `-Y` with axis `Y` and so on.

To determine which sensor is shifted, we can simply rotate the satellite around each of its axes and observe whether the associated sensors measure the same value each time. If not, then the sensor is shifted.

Though this solution might fail if the satellite is oriented at just the right angle for the shifted sensor to always measure a voltage of `0`, we did not observe this during our runs. It could be easily solved by performing 6 tests (one per sensor) instead of 3 (one per axis).

Here is a sample script implementing the method described above:

```python
def check_axis(p, axis):
    angle = [0, 0, 0]
    r_plus = []
    r_minus = []

    for x in range(0, 360, 90):
        angle[axis] = x
        m = rotate(p, *angle)
        r_plus.append(m[axis])
        r_minus.append(m[axis + 3])

    return (
        all(elem == r_plus[0] for elem in r_plus),
        all(elem == r_minus[0] for elem in r_minus),
    )

sensor_validity = []
for axis in range(3):
    sensor_validity += check_axis(p, axis)

invalid_sensor = sensor_validity.index(False)
print("The wrong sensor is sensor number", invalid_sensor)
```

**Note:** Not all functions are included in the snippets, but the full solution is provided at the end.

#### Finding out the shifted sensor's angle

To avoid over-complexifying the code (which is always error-prone, especially when lacking sleep), we decided to always start by assuming the same sensor is shifted (in this case, sensor `+X`). Basically, we looped over the code above until `invalid_sensor` was `0`.

With this in mind, we implemented two algorithms to discover the shift angle:

* A naive approach where we simply turn the satellite around each of its axes by a fixed step, and keep the angle for which the highest voltage was measured.
* Using a pseudo-dichotomy approach where we start with a large step in a broad angle interval, find the two angles which yield the highest voltage, and start again with a smaller step in this new interval.

In the end, both implementations allowed us to find the right angle. However, because the first approach was quicker to implement, it was the first to yield the flag and is thus described here.

To save some time, instead of rotating using a fixed step, a first iteration is performed with a larger step (e.g. 45 degrees) to find the approximate target angle, and then a more precise step is used. Moreover, since we know the function only has a single maximum, we can stop looking once a local maximum is found.

**Note:** It was important to save time for this challenge, otherwise the connection might timeout before the algorithm could complete.

Here is the implementation we ended up using:

```python
def optimize_axis(p, axis, sensor, start_angle, step_size):
    angle = start_angle.copy()
    value = rotate(p, *angle)[sensor]

    max_tries = 360 / step_size
    tries = 0

    # Step until either doing a full turn or finding a local maximum
    while tries < max_tries:
        new_angle = angle.copy()
        new_angle[axis] += step_size
        new_angle[axis] %= 360
        tries += 1

        new_value = rotate(p, *new_angle)[sensor]

        if new_value > value:
            value = new_value
            angle = new_angle
        elif value > new_value:
            break

    # Now turn the other way around to make sure we didn't miss anything
    while tries < max_tries:
        new_angle = angle.copy()
        new_angle[axis] -= step_size
        new_angle[axis] %= 360
        tries += 1

        new_value = rotate(p, *new_angle)[sensor]

        if new_value >= value:
            value = new_value
            angle = new_angle
        else:
            break

    return angle, value

def calibrate_invalid_sensor(p, start_angle=[0, 0, 0], precision=0.25):
    """
    Get shift angle for the invalid sensor (+X)
    """
    print("Calibrating invalid sensor...")
    out = start_angle.copy()

    # Start with a large step to find the approximate location of the max
    angle, _ = optimize_axis(p, 0, 0, out, 45)
    out[0] = angle[0]

    angle, _ = optimize_axis(p, 1, 0, out, 45)
    out[1] = angle[1]

    angle, _ = optimize_axis(p, 2, 0, out, 45)
    out[2] = angle[2]

    # Run again with the given precision
    angle, _ = optimize_axis(p, 0, 0, out, precision)
    out[0] = angle[0]

    angle, _ = optimize_axis(p, 1, 0, out, precision)
    out[1] = angle[1]

    angle, vmax = optimize_axis(p, 2, 0, out, precision)
    out[2] = angle[2]

    print("Optimal angle is", out, "with voltage of", vmax)
    return out

# Find the optimal angle for the sensor with an error
invalid_angle = calibrate_invalid_sensor(p)
```

#### Finding out the reference sensor's angle

Now that we know by which angle the satellite must be rotated to align the shifted sensor with the sun, we need a reference (since we don't know the satellite's initial rotation compared to the sun). We decided to reuse the method discussed above but with a sensor for which we know the vector: sensor `-X`.

A slight optimization in the search for the angle can be used: since we know the sensor is aligned with the `X` axis, there is no need to call `optimize_axis` with `axis` set to `0`. We also use a different start angle: since already know the angle for the `+X` sensor, the one for the `-X` sensor should be more or less the same rotated by 180 degrees along either the `Y` axis or the `Z` axis.

```python
def calibrate_valid_sensor(p, start_angle=[0, 180, 0], precision=0.25):
    """
    Get shift angle for the valid sensor (-X)
    """
    print("Calibrating valid sensor...")
    out = start_angle.copy()

    # We don't have to check axis X since we know it's correctly aligned
    angle, _ = optimize_axis(p, 1, 3, out, 45)
    out[1] = angle[1]

    angle, _ = optimize_axis(p, 2, 3, out, 45)
    out[2] = angle[2]

    angle, _ = optimize_axis(p, 1, 3, out, precision)
    out[1] = angle[1]

    angle, vmax = optimize_axis(p, 2, 3, out, precision)
    out[2] = angle[2]

    print("Optimal angle is", out, "with voltage of", vmax)
    return out

# Find the optimal angle for the opposite sensor
start_angle = invalid_angle.copy()
start_angle[1] += 180
valid_angle = calibrate_valid_sensor(p, start_angle=start_angle)
```

#### Computing the shifted sensor's vector norm

Using the information we have gathered, we now want to obtain the result needed to solve the challenge. The idea here is the following:

* We know the vector for the reference sensor.
* We know how to rotate from the original position to both the position where the reference sensor faces the Sun, and to where the shifted sensor faces the Sun.
* From this information, we can compute the rotation required to move fro one position to the other.
* We can apply this rotation to the reference vector to obtain the shifted sensor's vector.

Basically a lot of text for very few lines of code thanks to [NumPy](https://numpy.org). Out of ~~laziness~~ ingenuity to avoid errors late at night, we decided not to compute the rotation matrices ourselves. Indeed, when sending a message to rotate by the chosen angle, the server would be nice enough to send back the associated rotation matrix; all we had to do was parse it!

```python
import numpy as np

def get_rotation_matrix(p, dx, dy, dz):
    p.sendline(f"r:{dx},{dy},{dz}")
    p.recvuntil(b"< ")
    matrix_str = p.recvuntilS(">")
    p.recvuntil(b">")

    matrix_str = matrix_str.rstrip(">").strip()
    lines = matrix_str.split("\n")
    lines = [l.strip().strip("[").strip("]").strip() for l in lines]
    matrix = [
        [float(x) for x in line.split(" ") if x.strip()]
        for line in lines
    ]
    return np.array(matrix)

# Use the rotation matrices and the reference vector to compute the
# sensor's true vector
M1 = get_rotation_matrix(p, *invalid_angle)
M2 = get_rotation_matrix(p, *valid_angle)

R = np.matmul(M1, M2.T)
N2 = np.array([-1, 0, 0]).T
N1 = R.dot(N2)
N1 /= np.linalg.norm(N1)
```

If you are interested in the math behind computing `N1` from `M1`, `M2`, and `N2`, here is a simple proof:

```
Let N0 be the vector representing the starting position of the satellite
By definition, we have:
M1.N0 = N1
M2.N0 = N2

Moreover, since all rotation matrices are invertible:
    M1.N0 = N1
<=> (M1^-1).M1.N0 = (M1^-1).N1
<=> N0 = tM1.N1  // The inverse of a rotation matrix is its transpose

Thus, using the same reasoning for M2 and N2, the following holds true:
    N0 = tM1.N1
<=> tM2.N2 = tM1.N1
<=> N2 = t(tM2).tM1.N1
<=> N2 = M2.tM1.N1  // The transpose of the transpose is the original matrix
<=> N2 = R.N1 where R = M2.tM1

Finally, by definition of N1:
N2 = R.N1 where R = M2.tM1 and N1 = t[-1 0 0]
```

#### Obtaining the flag

Putting everything together, here is what little code is missing to obtain the flag:

```python
p.sendline(f"s:{N1[0]},{N1[1]},{N1[2]}")

try:
    while True:
        print(p.recvS(4096), end="")
except (KeyboardInterrupt, EOFError):
    pass
finally:
    print("")
    p.close()
```

And here is the output of the script:

```
[+] Opening connection to main-fleet.satellitesabove.me on port 5005: Done
Voltage estimate: 0.3688902275745456
The wrong sensor is sensor number 0
Calibrating invalid sensor...
Optimal angle is [306.5, 334.25, 314.75] with voltage of 0.3690309803764774
Calibrating valid sensor...
Optimal angle is [306.5, 228.5, 353.25] with voltage of 0.3690306392227042
Error = [0.00801146], component 0 is correct 
Error = [0.00141745], component 1 is correct 
Error = [0.00021337], component 2 is correct 
Here is your flag!!flag{uniform334275victor2:GAbl0m1OnP4dSlJvP6XjcudlGccerDhy6US8MXT6FWzJKJPNsZYvOf-HH-_X023u4PNC_uxsSszgBAa2NsVXisA}
[*] Closed connection to main-fleet.satellitesabove.me port 5005
```
