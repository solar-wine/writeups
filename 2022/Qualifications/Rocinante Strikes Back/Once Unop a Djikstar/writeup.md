# HACK-A-SAT 3: Once Unop a Djikstar

* **Category**: Rocinante Strikes Back
* **Points:** 131
* **Solves:** 27
* **Description:**

> Great, the fancy new Starlunk constellation won't route my packets anymore, right before our big trip.
>
> The StarlunkHacks forum thread had a sketchy looking binary. Might as well download that before we leave.
>
> Why did I think working on my honeymoon was a good idea...

> You'll need these files to solve the challenge.
>
> https://static.2022.hackasat.com/iprh5d6hcl0ijycqme1pqd25ynht

The remote server provides an additional description:

> You were on your way to your honeymoon in Bora Bora when your ship, ShippyMcShipFace, breaks down. You find yourself stranded in the middle of the Pacific Ocean.
>
> Thankfully you have just subscribed to the new global Starlunk network for a very affordable $110/month! Unfortunately, adversaries have corrupted the binary that is used to determine what string of satellites to route packets through within the Starlunk network. Because you have been spending countless hours on Youtube learning about the new network, you know that the nearest base station to you is in Honolulu, Hawaii. You also managed to find the corrupted binary on the internet before you left for your trip. You and all those aboard ShippyMcShipFace are counting on you to patch the binary so that you can uncover the route to send your packets in order to get help. 
>
> Do you have what it takes to save yourself and those aboard ShippyMcShipFace?
>
> Please submit the resulting route from ShippyMcShipFace to Honolulu. Only include Satellite ID's with the 'Starlunk-' omitted. For instance if the output from the corrected binary was: 
>
> ShippyMcShipFace
>
> Starlunk-00-901
>
> Starlunk-06-22
>
> Starlunk-105-38
>
> Honolulu
>
> You would submit: '00-901, 06-22, 105-38' without the quotes.
> Your answer:

## Write-up

_Write-up by Solar Wine team_

The challenge provides a x86-64 Rust program which is corrupted (some instructions were replaced with `NOP`), 3 CSV files and a shell script containing a command to run the program with the files:

```sh
./starlunk ShippyMcShipFace Honolulu gateways.csv sats.csv users.csv
```

Each file gives the distance between two nodes. `gateways.csv` contains distances from Honolulu:

```text
Source,Dest,Range
Honolulu,Starlunk-21-15,1867.46987808192
Honolulu,Starlunk-21-16,1959.72070327412
Honolulu,Starlunk-22-15,1365.92203974943
...
```

`sats.csv` contains distances between satellites:

```text
Source,Dest,Range
Starlunk-30-13,Starlunk-62-5,1112.67910099661
Starlunk-30-13,Starlunk-62-6,1697.15265130369
Starlunk-30-13,Starlunk-63-5,1370.11476857795
Starlunk-30-13,Starlunk-64-5,1787.84975181093
...
```

and `users.csv` contains distances from the `ShippyMcShipFace` user:

```text
Source,Dest,Range
ShippyMcShipFace,Starlunk-21-18,1972.19478055826
ShippyMcShipFace,Starlunk-22-17,1814.54535536371
ShippyMcShipFace,Starlunk-22-18,1783.05769496665
...
```

At first, this seems easy: load all the CSV files, find the shortest path, and that's it.
But the path was not considered as valid.
What is the program `starlunk` actually computing?

It implements a function named `once_unop_a_dijkstar::once_unop_a_dijkstar::run` which parses the content of the 3 CSV files and record the distances between nodes (identified in structures `once_unop_a_dijkstar::Node`).
However, the function which actually parses the distances, `parse_reader_file`, invokes two suspicious functions: `determine_target_type` and `get_target_traversal_cost`:

```rust
impl once_unop_a_dijkstar::once_unop_a_dijkstar {
    fn determine_target_type(target_name: &str) -> TargetType {
        let Some(value) = std::str::parse<i32>(target_name[target_name.len() - 1]) {
            match value % 3 {
                0 => TargetType::Starmander,
                1 => TargetType::Starmeleon,
                2 => TargetType::Starzard,
            }
        } else {
            TargetType::UserOrGatewayStation
        }
    }

    fn get_target_traversal_cost(t_distance: double, t_type: TargetType) -> double {
        t_distance * determine_type_weight(&t_type)
    }

    fn determine_type_weight(t_type: &TargetType) -> double {
        match t_type {
            TargetType::Starmander => 2.718,
            TargetType::Starmeleon => 3.141,
            TargetType::Starzard => 4.04,
            TargetType::UserOrGatewayStation => 1999.9,
        }
    }
}
```

So the distances are weighted according to the type of satellite which is used as target!

The shortest weighted path to Honolulu is then:

- `ShippyMcShipFace` to `Starlunk-63-6`: 654.877698384289 with Starmander weight 2.718
- `Starlunk-63-6` to `Starlunk-58-7`: 1888.77054209945 with Starmeleon weight 3.141
- `Starlunk-58-7` to `Starlunk-53-8`: 1340.68207660327 with Starzard weight 4.04
- `Starlunk-53-8` to `Starlunk-24-15`: 346.11386170069 with Starzard weight 4.04
- `Starlunk-24-15` to `'Honolulu`: 607.039251048805 with UserOrGatewayStation weight 1999.9

(Cumulated: 654.877698384289*2.718 + 1888.77054209945*3.141 + 1340.68207660327*4.04 + 346.11386170069*4.04 + 607.039251048805*1999.9 = 1228545.039620196)

The remote server accepted this path:

```text
63-6,58-7,53-8,24-15
You saved those aboard ShippyMcShipFace! Here's your flag:
flag{bravo600611golf3:GPdEcditK-2M16EKs6KIe86404oEWCUnQ8xfuF09Qsrft2aNiK9AbsDVhTdw--J0ax8dGyLZUUzhaS6EOp1mZwc}
```
