# HACK-A-SAT 2021: Satellite availability challenge

At the beginning of the competition, the only way we could earn points was by making sure our systems were up. The exact relation between systems availability and points earning rate was not explained by the organizers, so we experimented to try and understand what had an impact on the scoring system.

## Preserving energy

The flatsat is using 24 W from its power source when all components are enabled.
During the sunlight period (1 hour long), the solar panel array is delivering 31.5 W which leaves 7.5 W to charge the battery.
During the night period (30 minutes long), the battery is delivering 24 W.
This leads to losing approximately 10% of battery charge each orbital period.
The competition lasted 16 orbital periods, so it became clear that preserving energy was a problem.

We computed the power usage using the current and voltage from EPS (Electrical Power Supply) telemetry.
The most power-hungry components were:

  * 7.6 W: COMM Payload (SDR radio attached as the payload)
  * 5.3 W: TT&C COMM (Telemetry, Tracking and Command)
  * 5.2 W: Star tracker
  * 3.7 W: C&DH (Command and Data Handling System)
  * 2.5 W: ADCS (Attitude Determination And Control System)

### Disabling ADCS at night

At some point, seeing that the energy used during night periods was greater than
the recharge during sunlight periods, we tried to disable the ADCS at night.
Our reasoning was that since the ADCS was used to orient the
satellite's solar panels toward the sun, it was pointless at night 
because the sun was not visible. So, we tried to disable both the reaction
wheels and the star tracker at night, which would have saved a considerable
amount of energy. Alas, doing so resulted in the ADCS going red on the
scoreboard and reducing our points earning rate.
Definitely not what we wanted!

### Lowering payload's battery consumption

Knowing that the payload is an SDR radio and that its power
consumption is very high, we tried to find to reduce its output power.
We looked for commands that would allow us to communicate with the
SDR, but did not manage to find any.
