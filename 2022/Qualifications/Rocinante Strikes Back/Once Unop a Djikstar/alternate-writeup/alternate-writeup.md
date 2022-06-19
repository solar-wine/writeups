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

## Write-up

_Write-up by Solar Wine team_

For this challenge, we were provided with multiple files:

* A `starlunk` binary,
* Several CSV files (`sats.csv`, `users.csv`, and `gateways.csv`), each containing a list of Source,
  Destination, and Range values,
* A `run_starlunk.sh` script to start the `starlunk` binary with the right
  arguments.

We were asked to find the output of the corrected `starlunk` binary to obtain the flag. Indeed, running `run_starlunk.sh` would yield a `SIGSEGV` instead of a list of satellites.

Given the context and the name of the challenge, we assumed the goal was to find the shortest path to communicate from `ShippyMcShipFace` (the location of the stranded newlyweds) to `Honolulu` (the destination for the honeymoon) using the Starlunk constellation. Furthermore, the server was rather clear on the expected way of solving this challenge: we were supposed to "fix" the `starlunk` binary so it would run correctly and give us the solution.

We decided to explore (and mix) two solutions: patching `starlunk` and implementing the path-finding algorithm ourselves.

### Analyzing the crash

The `starlunk` binary is actually a 64-bit ELF with debug symbols:

```
$ file starlunk
starlunk: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2039d052338c50d7c5c8e11bc96a76f82d7505d7, for GNU/Linux 3.2.0, with debug_info, not stripped
```

A quick look at its content using [Ghidra](https://ghidra-sre.org) showed that it was build in [Rust](https://www.rust-lang.org). Thankfully, we had the debug symbols, which proved very handy to understand the program.

Before diving head-on into reverse engineering, we decided to start debugging the program to understand the reason why it crashed:

```
$ gdb --args ./starlunk ShippyMcShipFace Honolulu gateways.csv sats.csv users.csv
gdb-peda$ run
Program received signal SIGSEGV, Segmentation fault.
Stopped reason: SIGSEGV
gdb-peda$ backtrace
#0  0x00007fffffffd4c0 in ?? ()
#1  0x000055555556abbb in once_unop_a_dijkstar::run (args=...) at src/lib.rs:27
#2  0x0000555555567d20 in once_unop_a_dijkstar::main () at src/main.rs:14
[...]
```

To have more context and help us explore the crash, we ran the target again using gdb's [record and replay](https://sourceware.org/gdb/onlinedocs/gdb/Process-Record-and-Replay.html#Process-Record-and-Replay) feature:

```
gdb-peda$ break run
Breakpoint 1 at 0x16b4f: file src/lib.rs, line 27.
gdb-peda$ run
Breakpoint 1, once_unop_a_dijkstar::run (args=...) at src/lib.rs:27
gdb-peda$ record
gdb-peda$ continue
Continuing.

Program received signal SIGSEGV, Segmentation fault.
Stopped reason: SIGSEGV
gdb-peda$ reverse-stepi 
gdb-peda$ reverse-stepi 
   0x55555556aba8 <_ZN20once_unop_a_dijkstar3run17h11d8243fcbba55d9E+104>:	nop
   0x55555556aba9 <_ZN20once_unop_a_dijkstar3run17h11d8243fcbba55d9E+105>:	lea    rdi,[rsp+0x190]
   0x55555556abb1 <_ZN20once_unop_a_dijkstar3run17h11d8243fcbba55d9E+113>:	lea    rsi,[rsp+0x220]
=> 0x55555556abb9 <_ZN20once_unop_a_dijkstar3run17h11d8243fcbba55d9E+121>:	call   rax
   0x55555556abbb <_ZN20once_unop_a_dijkstar3run17h11d8243fcbba55d9E+123>:	jmp    0x55555556abe6 <_ZN20once_unop_a_dijkstar3run17h11d8243fcbba55d9E+166>
   0x55555556abbd <_ZN20once_unop_a_dijkstar3run17h11d8243fcbba55d9E+125>:	mov    rdi,QWORD PTR [rsp+0xf0]
   0x55555556abc5 <_ZN20once_unop_a_dijkstar3run17h11d8243fcbba55d9E+133>:	call   QWORD PTR [rip+0xbe76d]        # 0x555555629338
   0x55555556abcb <_ZN20once_unop_a_dijkstar3run17h11d8243fcbba55d9E+139>:	
    jmp    0x55555556b5d9 <_ZN20once_unop_a_dijkstar3run17h11d8243fcbba55d9E+2713>
```

We now had the exact location of the crash and the state of the program when it crashed. We thus disassembled the `once_unop_a_dijkstar::once_unop_a_dijkstar::run` function and quickly noticed several instructions were `nop`ed-out before the call leading to the crash. Based on the name of the challenge, it seemed like we were supposed to "un-`nop`" these instructions.

Using `grep`, we noticed that there didn't seem to be too many places replaced by `nop` instructions:

```
$ xxd starlunk | grep "9090 9090"
00016ba0: 9090 9090 9090 9090 9048 8dbc 2490 0100  .........H..$...
00016db0: 8bb4 24b0 0000 0090 9090 9090 9090 9090  ..$.............
00016dc0: 9090 9090 9090 9048 8dbc 2458 0300 00ff  .......H..$X....
00017210: 9c98 0100 488d bc24 3008 0000 9090 9090  ....H..$0.......
00017300: 9090 9090 9048 8dbc 2448 0800 0048 8db4  .....H..$H...H..
000173d0: 9090 9090 9090 9090 9090 9090 9090 9090  ................
000173e0: 9090 9090 9090 9090 9090 9090 9090 9048  ...............H
00018af0: 2418 f20f 1044 2418 9090 9090 900f 1f00  $....D$.........
00486ca0: 9090 9090 5805 0506 0369 5806 8282 4a82  ....X....iX...J.
```

We thus split our efforts into two endeavors: attempting to "fix" the binary, and attempting to understand and reimplement its logic in Python.

### Implementing Dijkstra

We started by parsing the CSV files in Python and using [SciPy](https://scipy.org)'s [Dijkstra implementation](https://docs.scipy.org/doc/scipy/reference/generated/scipy.sparse.csgraph.dijkstra.html) to find the shortest path between `ShippyMcShipFace` and `Honolulu`. However, this approach proved to be too naive, as the resulting path was not the expected one. We were still missing something, and we knew the `starlunk` binary had that information.

### Patching the binary

This seemed like the more tiresome way of solving this challenge, but proved useful to understand some of the logic of the program to help the re-implementation efforts. We were able to rebuild parts of the binary, though not all of it, before solving this challenge.

Initially, instead of patching the binary, we simply added breakpoints using gdb and fixed the values of the registers before continuing the execution:

```
$ break *0x55555556abb9
$ run
$ set $rax = 0x555555584ea0
$ break *0x55555556adc7
$ continue
$ set $edx = 0x88
$ set $rax = 0x7ffff7e55660
$ continue
```

This proved to work at first, but was too limited to solve all issues. We thus also implemented the following patches to the `starlunk` binary using Ghidra:

```
00118af8 48 83 c4 28     ADD        RSP, 0x28
00118afc c3              RET
```

```
001173cf 48 8b 84 24 78       MOV        RAX,qword ptr [RSP + 0x878]
            08 00 00
001173d7 48 89 84 24 f8       MOV        qword ptr [RSP + 0x8f8],RAX
            08 00 00
001173df 48 8b 84 24 80       MOV        RAX,qword ptr [RSP + 0x880]
            08 00 00
001173e7 48 89 84 24 00       MOV        qword ptr [RSP + 0x900],RAX
            09 00 00
```

While playing around like this, we encountered several interesting functions:

* `parse_reader_file`, accepting a `bool reverse` argument,
* `determine_target_type` and `determine_type_weight`, used when parsing the CSV files to compute the actual traversal cost,
* What looked like functions from the [pathfinding crate](https://rfc1149.net/devel/pathfinding.html) implementing Dijkstra's algorithm.

### Finding the shortest path

Using this gathered information, we were able to infer that:

* The "range" in the CSV files was not the weight used for the path-finding steps, and we had to reimplement the `determine_target_type` and `determine_type_weight` functions,
* `parse_reader_file` was called with `reverse` set to `True` for the `gateways.csv` file. This lead us to believe that paths weren't actually bidirectional, otherwise this flag would be useless.

We thus built our own function parsing the content of the CSV files, taking into account these particularities:

```python
import csv
import pathlib

BASEPATH = pathlib.Path(__file__).parent.resolve()

def parse_csv(out, path, reverse=False):
    def get_target_traversal_cost(name):
        weight_for_type = {
            0: 2.718,
            1: 3.141,
            2: 4.04,
            3: 1999.9,
        }
        last_char = name[-1]
        if last_char in "0123456789":
            return weight_for_type[int(last_char) % 3]
        return weight_for_type[3]

    def add(out, source, dest, r):
        if source not in out:
            out[source] = {}
        out[source][dest] = float(r) * get_target_traversal_cost(dest)

    with open(path, "r") as f:
        reader = csv.reader(f)
        lines = list(reader)[1:]

    for line in lines:
        if reverse:
            add(out, line[1], line[0], line[2])
        else:
            add(out, line[0], line[1], line[2])

    return out

# Build the graph of distances
distances = {}
parse_csv(distances, BASEPATH / "challenge" / "users.csv")
parse_csv(distances, BASEPATH / "challenge" / "sats.csv")
parse_csv(distances, BASEPATH / "challenge" / "gateways.csv", reverse=True)
```

We then did a bit of work to call SciPy's implementation:

```python
import numpy as np
from scipy.sparse.csgraph import dijkstra

# We want to convert the graph to a matrix so SciPy can use it
# First, build the list of all nodes
nodes = []
for k in distances:
    nodes.append(k)
    nodes += list(distances[k].keys())
nodes = sorted(list(dict.fromkeys(nodes)))

# Then, assign each node to an index
nodes_map = {nodes[i]: i for i in range(len(nodes))}

# Now, build the matrix itself
d = np.zeros((len(nodes), len(nodes)))
for src in nodes:
    i = nodes_map[src]

    # Some nodes may have no path leaving from them (e.g. Honolulu)
    if src not in distances:
        continue

    for dst in distances[src]:
        j = nodes_map[dst]
        d[i, j] = distances[src][dst]

# Ask SciPy to run the Dijkstra algorithm for us
# We only care about paths starting from ShippyMcShipFace, and given paths are
# considered directed (i.e. having a path from node A to node B does not mean
# there is a path from node B to node A)
_, predecessors = dijkstra(
    csgraph=d,
    directed=True,
    indices=nodes_map["ShippyMcShipFace"],
    return_predecessors=True,
)
```

All that was left to do was to rebuild the shortest path from the list of predecessors returned by Dijkstra:

```python
def find_path(src, dst, pred):
    path = [dst]
    current_node = dst
    while current_node != src:
        current_node = pred[current_node]
        if current_node < 0:
            raise Exception("No path found")
        path.append(current_node)
    return path[::-1]

path = find_path(
    nodes_map["ShippyMcShipFace"],
    nodes_map["Honolulu"],
    predecessors,
)

# Convert back from each node index to the node name
print([nodes[i] for i in path])
```

This allowed us to get the flag for this challenge, even though our `starlunk` binary still crashed without returning a proper result.
