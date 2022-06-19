import math
from pwn import remote
import numpy as np


TICKET = "ticket{uniform334275victor2:GGaIU03iD7VPR9A_CRNySE5ymxNyM1e0LN3cqPSQmILOW9nDudIipQF9DYDuksOtXw}"


def estimate_measured_voltage():
    """
    Compute the estimated voltage of a sensor facing the sun
    """
    H0 = 1360.8  # W/m^2 (https://en.wikipedia.org/wiki/Solar_constant)

    S = 10**-4  # m (1cm^2)
    Pr = H0 * S

    e = 0.1  # 10%
    P = e * Pr

    R = 10  # Ohm
    return math.sqrt(P * R)


def read_voltage(p):
    """
    Read (and parse) a voltage value
    """
    line = p.recvlineS().strip()
    return float(line.split(":")[-1])


def read_voltages(p):
    """
    Read voltage values for all sensors (as floats)
    """
    return (
        read_voltage(p),
        read_voltage(p),
        read_voltage(p),
        read_voltage(p),
        read_voltage(p),
        read_voltage(p),
    )


def rotate(p, dx, dy, dz):
    """
    Rotate the satellite by the given angles and return the new measured
    voltages
    """
    p.sendline(f"r:{dx},{dy},{dz}")
    p.recvuntil(b">")
    out = read_voltages(p)
    p.recvuntil(b">")
    return out


def get_rotation_matrix(p, dx, dy, dz):
    """
    Given a set of angles, retrieve the associated rotation matrix (as a numpy
    array)
    """
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


def check_axis(p, n):
    """
    Check whether the sensors on the given axis are correctly aligned
    """
    angle = [0, 0, 0]
    r_plus = []
    r_minus = []

    for x in range(0, 360, 90):
        angle[n] = x
        m = rotate(p, *angle)
        r_plus.append(m[n])
        r_minus.append(m[n + 3])

    return (
        all(elem == r_plus[0] for elem in r_plus),
        all(elem == r_minus[0] for elem in r_minus),
    )


def optimize_axis(p, axis, sensor, start_angle, step_size):
    """
    Find the angle for which the provided sensor has the highest voltage, using
    the provided step value (which gives a sense of the output's precision)
    """
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


def init():
    """
    Return a socket for which sensor +X is known to be invalid
    """
    # Connect to the challenge until the invalid sensor is the one
    # we want (it makes everything easier)
    invalid_sensor = -1
    while invalid_sensor != 0:
        p = remote("main-fleet.satellitesabove.me", 5005)
        p.settimeout(10)
        p.recvline()
        p.sendline(TICKET)

        # Banner
        p.recvuntil(b"(Format answers as a single float): ")
        print("Voltage estimate:", estimate_measured_voltage())
        p.sendline(str(estimate_measured_voltage()))

        p.recvuntil(b"The final answer should be a unit vector\n")
        sensor_validity = []
        for axis in range(3):
            sensor_validity += check_axis(p, axis)

        invalid_sensor = sensor_validity.index(False)
        print("The wrong sensor is sensor number", invalid_sensor)

    return p


if __name__ == "__main__":
    p = init()

    # Find the optimal angle for the sensor with an error
    invalid_angle = calibrate_invalid_sensor(p)

    # Find the optimal angle for the opposite sensor
    start_angle = invalid_angle.copy()
    start_angle[1] += 180
    valid_angle = calibrate_valid_sensor(p, start_angle=start_angle)

    # Use the rotation matrices and the reference vector to compute the
    # sensor's true vector
    M1 = get_rotation_matrix(p, *invalid_angle)
    M2 = get_rotation_matrix(p, *valid_angle)

    R = np.matmul(M1, M2.T)
    N2 = np.array([-1, 0, 0]).T
    N1 = R.dot(N2)
    N1 /= np.linalg.norm(N1)

    p.sendline(f"s:{N1[0]},{N1[1]},{N1[2]}")

    try:
        while True:
            print(p.recvS(4096), end="")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        print("")
        p.close()
