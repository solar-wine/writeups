# SPACE SECURITY CHALLENGE 2020 HACK-A-SAT: Digital Filters, Meh

* **Category:** Astronomy, Astrophysics, Astrometry, Astrodynamics, AAAA
* **Points:** 104
* **Solves:** 37
* **Description:**

> Included is the simulation code for the attitude control loop for a satellite in orbit. A code reviewer said I made a pretty big mistake that could allow a star tracker to misbehave. Although my code is flawless, I put in some checks to make sure the star tracker can't misbehave anyways.
> 
> Review the simulation I have running to see if a startracker can still mess with my filter. Oh, and I'll be giving you the attitude of the physical system as a quaternion, it would be too much work to figure out where a star tracker is oriented from star coordinates, right?
>  
> You'll need these files to solve the challenge.
> [Download](https://static.2020.hackasat.com/fd578f9dee5b5ac45b0717a1c7739606bd27013b/src.tar.gz)

## Introduction

_Write-up by Solar Wine team_

The tarball contain several ``.m`` (MATLAB) files implementing a closed-loop transfer function used to control the attitude of a satellite. The loop is the following one:

``` {.text samepage=true}
Target                                                                     Actual
attitude      Error                                                        attitude
                           +------------------+                                         
target    +-+         err  |                  |  q_accel
+---------> +-------------->   controller.m   +----------------------------+----->
          +^+              |                  |                            |
           |               +------------------+                            |
           |                                                               |
           |                                                               |
           |      +-------------+          +-----------------------+       |
           |      |             |          |                       |       |
           +------+   Kalman    <----------+      Startracker      <-------+
                x |             |     q_att|                       |  actual
                  +-------------+          +-----------------------+
                                                       ^
                                                       |
                                                       +
                                             WE CONTROL THIS MODULE
```

In this scenario, we have somewhat the control of the startracker module, the "sensor" module in control theory:

``` matlab
function [ q ] = startracker(model) 
  q = model.q_att;
  disp([q.w, q.x, q.y, q.z]);
  fflush(stdout);
  % Get Input
  q = zeros(4,1);
  for i = 1:4
    q(i) = scanf("%f", "C");
  endfor 
  q = quaternion(q(1), q(2), q(3), q(4));
  %q.w = q.w + normrnd(0, 1e-8);
  %q.x = q.x + normrnd(0, 1e-8);
  %q.y = q.y + normrnd(0, 1e-8);
  %q.z = q.z + normrnd(0, 1e-8);
  
  q = q./norm(q);
  
endfunction
```

During each step of the simulation, the program outputs the actual attitude as quaternion and asks for the "sensor measurement" also as a quaternion. What's a quaternion? A quaternion is a mathematical object useful to describe 3D rotations using 4 variables (w,x,y,z) and which is extremely popular as a coordinate system in robotics since it solves the "Gimbal Lock issue".


What's interesting is the following snippet of code has been commented:

``` matlab

    % Get Observations
    q_att = startracker(i, actual);
    %err = quat2eul(quat_diff(q_att, target.q_att))';
    %if max(abs(err)) > err_thresh
    %    disp("Error: No way, you are clearly lost, Star Tracker!");
    %    break;
    %endif
```

We directly control what ``startracker`` returns and the error check is not done here right after the sensor but when the signal has been filtered by the Kalman filter: 

``` matlab

    % Get Observations
    q_att = startracker(i, actual);
    %err = quat2eul(quat_diff(q_att, target.q_att))';
    %if max(abs(err)) > err_thresh
    %    disp("Error: No way, you are clearly lost, Star Tracker!");
    %    break;
    %endif

    [q_rate, q_acc] = gyro(actual.q_rate, q_accel);
    z = [ 
        quat2eul(q_att)'
        q_rate.x, q_rate.y, q_rate.z
        q_acc.x,  q_acc.y,  q_acc.z 
    ];

    % Filter
    for j = 1:3
        [x(:,j), Ps(:,:,j), _] = kalman_step(filters(j), Ps(:,:,j), x(:,j), u(j), z(:,j));
    endfor

    % Calculate Error
    q_est = eul2quat(x(1,:));
    err = quat2eul(quat_diff(q_est, target.q_att))';
    % Check error bounds
    if max(abs(err)) > err_thresh
        disp("Error: Estimator error too large... Goodbye");
    	break;
    endif
```


So ... what can we do here? Well, in my student years I remember Kalman filters were all the rage for controlling consumer quadcopters's attitude since they are pretty easy to implement and can work with dirt-cheap sensors. However, there is a catch: you can't use, let's say, only accelerometers with a Kalman filter to correct attitude since **it can't correct absolute errors and this will cause the device to drift over time**. Usually, accelerometers are coupled with gyroscopes and/or magnetometers in order to prevent this drift from happening.

The challenge here is to slowly feed the satellite slightly incorrect values that will not be sufficiently removed by the Kalman filter and over time make the sat go belly up!

## Tourne Toi Benoit

The objective here is to rotate the sat over 22° degrees along the **second** axis y: 

``` matlab
    % Check we're still safe...
    [v,a] = q2rot(quat_diff(actual.q_att, target.q_att));
    if abs(v(2)*a) >  (pi/8)
        disp("Uh oh, better provide some information!");
        disp(getenv("FLAG"))
        break;
    endif
```
(yes, matlab is indexing array from 1 to n)


Fortunately, expressing a rotation using a quaternion is dead simple: just multiply them. Here's a skeleton of a script slowly rotating the satellite over time:

``` Python
#! /usr/bin/python3

import os
import re
import random
import sys

import pwn # https://github.com/Gallopsled/pwntools
from pyquaternion import Quaternion # http://kieranwynn.github.io/pyquaternion/

TICKET=os.environ["TICKET"]

def ticket(p):
    p.recvuntil(b'Ticket please:')
    p.sendline(TICKET)
    print("Ticket sent.")

def handle_input(p):

    while True:
      l = p.recvline()

      # SUCCESS
      if l.startswith(b"Uh oh, better provide some information!"):
      	print(l)
        flag = p.recvline()
        print(flag)
        sys.exit(0)

      # FAIL
      elif l.startswith(b"Error: Estimator error too large... Goodbye"):
      	print(l)
        sys.exit(1)

      # empty line => /ignore
      if len(l.rstrip(b'\n')):
        break

    # parse digits
    m = re.match(r'\s+(\S+)'*4, l.decode('utf-8'))
    digits = list(map(float, m.groups()))
    print("Received : %s" % digits)
    return digits

def senddigits(p, quat):
    p.send("%f,%f,%f,%f\n" % (quat.w, quat.x, quat.y, quat.z))

if __name__ == '__main__':
    p = pwn.remote('filter.satellitesabove.me',5014)
    ticket(p)
    p.recvline() # empty line

    step = 1
    while True:

        digits = handle_input(p)
        q = Quaternion(*digits)

        # Rotate satellite
        new_quat = q*Quaternion(axis=[0, 1, 0], degrees=15)

        print("[%d] sent %f,%f,%f,%f" % (step, new_quat.w, new_quat.x, new_quat.y, new_quat.z))
        senddigits(p, new_quat)

        step+=1
        if step > 2400:
            print("[x] simulation ended : FAIL")
            sys.exit(0)
```

And here's the result:

```
$ python3 too_slow.py
[+] Opening connection to filter.satellitesabove.me on port 5014: Done
Ticket sent.
Received : [0.99903, 0.04399, 0.0, 0.0]
[1] sent 0.990483,0.043614,0.130400,0.005742
Received : [0.99903, 0.04402, 0.0, 0.0]
[2] sent 0.990483,0.043643,0.130400,0.005746
Received : [0.99903, 0.04404, 0.0, 0.0]
[... snipped for clarity ...]
[2400] sent 0.992956,0.113224,0.034781,0.002856
[x] simulation ended : FAIL
```

I managed to slightly move the sat, but unfortunately the simulation time is finite: only 2400 steps are computed. So we can try to be more aggressive and increase the rotation from 15 degrees to 45 degrees:


```
$ python3 too_fast.py
[+] Opening connection to filter.satellitesabove.me on port 5014: Done
Ticket sent.
Received : [0.99903, 0.04399, 0.0, 0.0]
[1] sent 0.922983,0.040641,0.382312,0.016834
Received : [0.99903, 0.04402, 0.0, 0.0]
[2] sent 0.922983,0.040669,0.382312,0.016846
Received : [0.99903, 0.04404, 0.0, 0.0]
[3] sent 0.922983,0.040688,0.382312,0.016853
Received : [0.99903, 0.04407, 0.0, 0.0]
[... snipped for clarity ...]
[22] sent 0.923128,0.041195,0.381901,0.017032
Received : [0.999004635, 0.0446039, -0.000479317, -3.2373e-05]
[23] sent 0.923143,0.041221,0.381860,0.017039
Received : [0.999003404, 0.044630975, -0.000523661, -3.5365e-05]
[24] sent 0.923159,0.041247,0.381818,0.017047
b'Error: Estimator error too large... Goodbye\n'
```

Well in that example we are too aggressive and we are caught by the error check. So how to do it? Well, I did manually bruteforce heuristics on my machine until I found one that worked. I know it's not intellectually fulfilling, but sometimes you need to be efficient, not intelligent :D

Here's my heuristic, which work on our team simulation (there is a random seed different for every team): I start small and increase the rotation over "time".

```python
	if step < 500:
      new_quat = q*Quaternion(axis=[0, 1, 0], degrees=15)
    elif step < 1000:
      new_quat = q*Quaternion(axis=[0, 1, 0], degrees=30)
    else:
      new_quat = q*Quaternion(axis=[0, 1, 0], degrees=40)
```

And the result:

```
$ python3 solution.py
[+] Opening connection to filter.satellitesabove.me on port 5014: Done
Ticket sent.
Received : [0.99903, 0.04399, 0.0, 0.0]
[1] sent 0.990483,0.043614,0.130400,0.005742
Received : [0.99903, 0.04402, 0.0, 0.0]
[2] sent 0.990483,0.043643,0.130400,0.005746
Received : [0.99903, 0.04404, 0.0, 0.0]
[... snipped for clarity ...]
[1719] sent 0.984792,0.089937,0.148156,0.012068
Received : [0.976058, 0.08867, -0.197662, -0.019433]
[1720] sent 0.984799,0.089969,0.148090,0.012066
Received : [0.976042, 0.088698, -0.197726, -0.019445]
[1721] sent 0.984806,0.089999,0.148024,0.012064
b"Uh oh, better provide some information!"
b'flag{uniform91635foxtrot:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ}\n'
```

## References

* https://en.wikipedia.org/wiki/Quaternion
* https://en.wikipedia.org/wiki/Gimbal_lock
