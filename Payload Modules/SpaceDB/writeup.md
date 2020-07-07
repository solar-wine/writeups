# SPACE SECURITY CHALLENGE 2020 HACK-A-SAT: SpaceDB

* **Category:** Payload Modules
* **Points:** 79 points
* **Solves:** 53
* **Description:**

> The last over-the-space update seems to have broken the housekeeping on our 
> satellite. Our satellite's battery is low and is running out of battery fast. 
> We have a short flyover window to transmit a patch or it'll be lost forever. 
> The battery level is critical enough that even the task scheduling server has 
> shutdown. Thankfully can be fixed without without any exploit knowledge by using 
> the built in APIs provided by kubOS. Hopefully we can save this one!
>
> Note: When you're done planning, go to low power mode to wait for the next 
> transmission window
>
>  Connect to the challenge on `spacedb.satellitesabove.me:5062`. Using netcat, 
>  you might run `nc spacedb.satellitesabove.me 5062`

## Write-up

_Write-up by Solar Wine team_

Once again, the solution was found while trying to get a better understanding of 
the internals and fiddling around in Burp, so no _pwntools_ script here! ;-O

Connecting to the service seems to start a private [kubOS](https://www.kubos.com/) 
instance, exposing telemetry data over GraphQL:

```
$ nc spacedb.satellitesabove.me 5062
Ticket please:
ticket{november41292tango:GNaaZ_D_8XhoR5hCScHJzX32mfZsRUou84FuCvLi1Yv7ZxyIfgnAWPlaDYtNnhMuCA}
### Welcome to kubOS ###
Initializing System ...

** Welcome to spaceDB **
-------------------------

req_flag_base  warn: System is critical. Flag not printed.

critical-tel-check  info: Detected new telemetry values.
critical-tel-check  info: Checking recently inserted telemetry values.
critical-tel-check  info: Checking gps subsystem
critical-tel-check  info: gps subsystem: OK
critical-tel-check  info: reaction_wheel telemetry check.
critical-tel-check  info: reaction_wheel subsystem: OK.
critical-tel-check  info: eps telemetry check.
critical-tel-check  warn: VIDIODE battery voltage too low.
critical-tel-check  warn: Solar panel voltage low
critical-tel-check  warn: System CRITICAL.
critical-tel-check  info: Position: GROUNDPOINT
critical-tel-check  warn: Debug telemetry database running at: 18.191.160.21:15969/tel/graphiql
```

The lines `VIDIODE battery voltage too low` and `Solar panel voltage low` seem 
to explain why the system is in `CRITICAL` mode, as they don't deliver enough tension to the satellite
to operate in a normal way ([https://docs.kubos.com/1.21.0/deep-dive/apis/device-api/gomspace-p31u/p31u_api.html#_CPPv4N20eps_battery_config_t20batt_criticalvoltageE](https://docs.kubos.com/1.21.0/deep-dive/apis/device-api/gomspace-p31u/p31u_api.html#_CPPv4N20eps_battery_config_t20batt_criticalvoltageE)).

The [documentation of the Telemetry Database Service](https://docs.kubos.com/1.21.0/ecosystem/services/telemetry-db.html#querying-the-service) describes how the data is organized 
in the database and which queries / mutations are available.

After browsing on the GraphiQL instance, the following query was used to display 
every telemetry entry available:

```json
query { 
    telemetry{
    timestamp, 
        subsystem, 
        parameter, 
        value
    } 
}
```

Looking for references to `VIDIODE` leaves us with only one entry of interest:

```json
{
  "data": {
    "telemetry": [
...
      {
        "timestamp": 1590427585.484284,
        "subsystem": "eps",
        "parameter": "VIDIODE",
        "value": "6.47"
      },
...
```

As described in the documentation, a mutation named `insert` allows modifying 
telemetry entries. For instance, it is possible to set the entry `VIDIODE` of
the `eps` subsystem to `8`:

```
mutation {
  insert(subsystem: "eps", parameter: "VIDIODE", value: "8") { 
    success, errors 
  } 
}
```

This action will immediately be detected by the satellite, which is now 
operating in normal mode:

```
critical-tel-check  info: Detected new telemetry values.
critical-tel-check  info: Checking recently inserted telemetry values.
critical-tel-check  info: Checking gps subsystem
critical-tel-check  info: gps subsystem: OK
critical-tel-check  info: reaction_wheel telemetry check.
critical-tel-check  info: reaction_wheel subsystem: OK.

critical-tel-check  info: eps telemetry check.
critical-tel-check  warn: Solar panel voltage low
critical-tel-check  info: eps subsystem: OK
critical-tel-check  info: Position: GROUNDPOINT
critical-tel-check  warn: System: OK. Resuming normal operations.
critical-tel-check  info: Scheduler service comms started successfully at: 18.191.160.21:15969/sch/graphiql
```

The battery will slowly discharge so the satellite will fallback in `CRITICAL` 
mode, closing the scheduler interface. It is required to regularly replay the 
`VIDIODE` query until the satellite stops responding or you get the flag (pick 
one between: good muscular memory, Burp Suite, a script).

The new interface (`host:port/sch/graphiql`) is also based on GraphiQL, and allows sending GraphQL
requests handled by the [Schduler Service](https://docs.kubos.com/1.21.0/ecosystem/services/scheduler.html).

In Kubos' terminology, each _mode_ is associated to a _schedule_ made of 
_tasks_. Everything can be enumerated in a single query:

```
query {
  availableModes {
    name, 
    path, 
    lastRevised, 
    schedule {
      tasks {
        description, 
        delay, 
        time, 
        period, 
        app {
          name, 
          args, 
          config
        }
      }, 
      path, 
      filename, 
      timeImported
    }, 
    active
  }
}
```

```json
{
  "data": {
    "availableModes": [
      {
        "name": "low_power",
        "path": "/challenge/target/release/schedules/low_power",
        "lastRevised": "2020-05-25 18:02:50",
        "schedule": [
          {
            "tasks": [
              {
                "description": "Charge battery until ready for transmission.",
                "delay": "5s",
                "time": null,
                "period": null,
                "app": {
                  "name": "low_power",
                  "args": null,
                  "config": null
                }
              },
              {
                "description": "Switch into transmission mode.",
                "delay": null,
                "time": "2020-05-25 18:59:40",
                "period": null,
                "app": {
                  "name": "activate_transmission_mode",
                  "args": null,
                  "config": null
                }
              }
            ],
            "path": "/challenge/target/release/schedules/low_power/nominal-op.json",
            "filename": "nominal-op",
            "timeImported": "2020-05-25 18:02:50"
          }
        ],
        "active": false
      },
      {
        "name": "safe",
        "path": "/challenge/target/release/schedules/safe",
        "lastRevised": "1970-01-01 00:00:00",
        "schedule": [],
        "active": false
      },
      {
        "name": "station-keeping",
        "path": "/challenge/target/release/schedules/station-keeping",
        "lastRevised": "2020-05-25 18:02:50",
        "schedule": [
          {
            "tasks": [
              {
                "description": "Update system telemetry",
                "delay": "35s",
                "time": null,
                "period": "1m",
                "app": {
                  "name": "update_tel",
                  "args": null,
                  "config": null
                }
              },
              {
                "description": "Trigger safemode on critical telemetry values",
                "delay": "5s",
                "time": null,
                "period": "5s",
                "app": {
                  "name": "critical_tel_check",
                  "args": null,
                  "config": null
                }
              },
              {
                "description": "Prints flag to log",
                "delay": "0s",
                "time": null,
                "period": null,
                "app": {
                  "name": "request_flag_telemetry",
                  "args": null,
                  "config": null
                }
              }
            ],
            "path": "/challenge/target/release/schedules/station-keeping/nominal-op.json",
            "filename": "nominal-op",
            "timeImported": "2020-05-25 18:02:50"
          }
        ],
        "active": true
      },
      {
        "name": "transmission",
        "path": "/challenge/target/release/schedules/transmission",
        "lastRevised": "2020-05-25 18:02:50",
        "schedule": [
          {
            "tasks": [
              {
                "description": "Orient antenna to ground.",
                "delay": null,
                "time": "2020-05-25 18:59:50",
                "period": null,
                "app": {
                  "name": "groundpoint",
                  "args": null,
                  "config": null
                }
              },
              {
                "description": "Power-up downlink antenna.",
                "delay": null,
                "time": "2020-05-25 19:00:10",
                "period": null,
                "app": {
                  "name": "enable_downlink",
                  "args": null,
                  "config": null
                }
              },
              {
                "description": "Power-down downlink antenna.",
                "delay": null,
                "time": "2020-05-25 19:00:15",
                "period": null,
                "app": {
                  "name": "disable_downlink",
                  "args": null,
                  "config": null
                }
              },
              {
                "description": "Orient solar panels at sun.",
                "delay": null,
                "time": "2020-05-25 19:00:20",
                "period": null,
                "app": {
                  "name": "sunpoint",
                  "args": null,
                  "config": null
                }
              }
            ],
            "path": "/challenge/target/release/schedules/transmission/nominal-op.json",
            "filename": "nominal-op",
            "timeImported": "2020-05-25 18:02:50"
          }
        ],
        "active": false
      }
    ]
  }
}
```

The current mode is `station-keeping`. A bunch of GraphQL migrations are defined by 
the scheduler (they are all described in the documentation): 

  - `createMode`
  - `removeMode`
  - `activateMode`
  - `importTaskList`
  - `importRawTaskList`
  - `removeTaskList`
  - `safeMode`

And the following actions can be called

- `low_power`: charge battery until ready for transmission
- `activate_transmission_mode`: switch into transmission mode
- `update_tel`: update system telemetry
- `critical_tel_check`: trigger safemode on critical telemetry values
- `request_flag_telemetry`: prints flag to log
- `groundpoint`: orient antenna to ground
- `enable_downlink`: power-up downlink antenna
- `disable_downlink`: power-down downlink antenna
- `sunpoint`: orient solar panels at sun

We first oriented the solar panels by adding the task `sunpoint` to the mode 
`station-keeping` to avoid the second warning:

```
mutation {
  sunpoint: importRawTaskList (
    name: "fufu2"
    mode: "station-keeping"
    json: "{\"tasks\": [{\"app\":{\"name\":\"sunpoint\",\"args\":null,\"config\":null},\"description\":\"a\",\"delay\":\"1s\"}]}"
  )
   {
        success
        errors
    }
}
```

This action is immediately acknowledged on the console:

```
sunpoint  info: Adjusting to sunpoint...
sunpoint  info: [2020-05-25 18:06:48] Sunpoint panels: SUCCESS
```

After reading the challenge's description again (`Note: When you're done planning, go` `to 
low power mode to wait for the next transmission window`), we stopped looking around
for vulnerabilities and tried to think of a way to transmit the output of
`request_flag_telemetry`.

Using the previous output of the query `availableModes`, a call to the task 
`request_flag_telemetry` was added right between `groundpoint` and `enable_downlink`
of the mode `transmission`, which is automatically enabled by the task 
`activate_transmission_mode` of mode `low_power`:

```
mutation {
    flag: importRawTaskList (
    name: "fufu2"
    mode: "transmission"
    json: "{\"tasks\": [{\"app\":{\"name\":\"request_flag_telemetry\",\"args\":null,\"config\":null},\"description\":\"foo\",\"time\":\"2020-05-25 19:00:05\"}]}"
  )
   {
        success
        errors
    }

    activateMode(name: "low_power") {
        success, errors
    }
}
```

After executing the mutation `activateMode`, the satellite indeed went into 
mode `low_power` and gave us the flag:

```
Low_power mode enabled.
Timetraveling.

Transmission mode enabled.

Pointing to ground.
Transmitting...

----- Downlinking -----
Recieved flag.
flag{november41292tango:GN_jhChTaWnjXPRwbL5HrjpQf0N0PVlfsq0HyodCDa14E4H930IlRKXA3hDWjepyhyHBSgXWCSO_8LdTSJ6qZCM}

Downlink disabled.
Adjusting to sunpoint...
Sunpoint: TRUE
Goodbye
```
