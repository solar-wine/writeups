from scipy.spatial.transform import Rotation
import numpy as np
import ephem as j2000
import math

# Problem parameters
window_time = "2020-08-09 00:%02d:%02d"
MAX_ERROR = 0.5
TLE = (
    "DEFCON28 SAT",
    "1 46266U 19031D   20218.52876597 +.00001160 +00000-0 +51238-4 0  9991",
    "2 46266 051.6422 157.7760 0010355 123.0136 237.1841 15.30304846055751"
)
sat = j2000.readtle(TLE[0], TLE[1], TLE[2])
boresight  = np.array([0.007196099926469, -0.999687104708689, -0.023956394240496])
boresight /= np.linalg.norm(boresight)
moon = j2000.Moon()

# Function to convert from right ascension, declination and distance to
# cartesian coordinates.
def radec2cart(ra, dec, dist):
    x = math.cos(dec) * math.cos(ra)
    y = math.cos(dec) * math.sin(ra)
    z = math.sin(dec)
    return np.array([x, y, z]) * dist

# Initialize Z best angle
best_angle = 2 * math.pi
z_vector  = np.array([0, 0, 1])

# The window of opportunity is 600 seconds
for i in range(600):
    time = window_time % (i / 60 + 20, i % 60)

    # Compute Moon and satellite position at current time
    moon.compute(time)
    sat.compute(time)

    # Use cartesians coordinates
    moon_xyz = radec2cart(moon.ra, moon.dec, moon.earth_distance * j2000.meters_per_au)
    sat_xyz  = radec2cart(sat.ra, sat.dec, sat.elevation + j2000.earth_radius)

    # Compute unit vectors for the target (Moon) and satellite position relative to Earth
    target   = np.array(moon_xyz - sat_xyz)
    target  /= np.linalg.norm(target)
    sat_unit = sat_xyz / np.linalg.norm(sat_xyz)

    # Generate the rotation axis with a cross product
    axis = np.cross(boresight, target)
    axis /= np.linalg.norm(axis)

    # Get the angle using the dot product
    arc = np.dot(boresight, target)
    angle = np.arccos(arc)
    R = Rotation.from_rotvec(axis * angle).as_dcm()

    # Compute the position of the satellite Z vector after our initial rotation
    z_rotated = np.dot(R, z_vector)

    # Project the rotated Z vector and the satellite to Earth vector onto the plane defined by
    # the target vector
    z_rot_proj = z_rotated - np.dot(z_rotated, target) * target
    sat_proj   = sat_unit  - np.dot(sat_unit,  target) * target

    # Use dot product to find the angle between them
    arc = np.dot(z_rot_proj, sat_proj)
    angle = np.arccos(arc)

    # We need to check the sign against the orientation of the target
    if np.dot(target, np.cross(z_rot_proj, sat_proj)) < 0:
        angle -= angle

    # Get the rotation matrix defined by the target vector and angle previously computed to
    # align the satellite Z vector with the center of the Earth
    Rp = Rotation.from_rotvec(target * angle).as_dcm()

    # Get the final rotation matrix by multiplying the previously computed matrices
    Rr = np.dot(Rp, R)
    
    # Compute the angle between the Z satellite vector and the satellite to Earth vector
    z_rotated = np.dot(Rr, z_vector)
    arc = np.dot(z_rotated, sat_unit)
    z_angle = (np.arccos(arc) * 180) / math.pi
 
    # Find the minimal angle during the window of opportunity
    if z_angle < best_angle:
        best_angle  = z_angle
        best_time   = time
        best_matrix = Rr
        best_target = target

# Reset the satellite to the best found time
sat.compute(best_time)
sat_xyz  = radec2cart(sat.ra, sat.dec, sat.elevation + j2000.earth_radius)
sat_unit = sat_xyz / np.linalg.norm(sat_xyz)

# Z and the Earth to satellite vectors are now on the same plane as the target vector.
# Rotate to lower the error on the Z axis based on the allowed error on the target.
z_rotated = np.dot(best_matrix, z_vector)
axis = np.cross(z_rotated, sat_unit)
axis /= np.linalg.norm(axis)

# Keep a small margin to avoid being too far from the Moon
MARGIN = 1e-6
angle = min(MAX_ERROR *(1 - MARGIN), best_angle) * math.pi / 180
Rq = Rotation.from_rotvec(axis * angle).as_dcm()
best_matrix = np.dot(Rq, best_matrix)

# Compute the final angle errors
z_rotated = np.dot(best_matrix, z_vector)
arc = np.dot(z_rotated, sat_unit)
z_angle = (np.arccos(arc) * 180) / math.pi
print("Z error:", z_angle)
target_optz = np.dot(best_matrix, boresight)
arc = np.dot(target_optz, best_target)
target_err = (np.arccos(arc) * 180) / math.pi
print("Moon error:", target_err)

print(best_time)
print(', '.join([str(x) for x in Rotation.from_dcm(best_matrix).as_quat()]))
