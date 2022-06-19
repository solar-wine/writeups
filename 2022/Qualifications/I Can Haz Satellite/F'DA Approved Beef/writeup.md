# HACK-A-SAT 3: F'DA Approved Beef

* **Category**: I Can Haz Satellite
* **Points:** 150
* **Solves:** 22
* **Description:**

## Problem description


This challenge starts by connecting to a TCP service, which first asks for our
team ticket, and then provides us with:

* an HTTP endpoint where an instance of
  [F'Prime](https://nasa.github.io/fprime/) instance is reachable. Through this
  interface, we can easily send telecommands, and receive telemetry.
* a TCP endpoint for a CLI interface (which we did not understand how to use).

```
Wait for system to initialized
Challenge Web Page Starting at http://44.196.58.114:18550/
CLI available at 44.196.58.114:18551
Now F'DA Approved Beef
Get the system to return flag in telemetry to win
Time remaining to solve: 900 seconds
```

## Recon

A command called `flagSvr.FS_FlagEnable` looks particularly interesting. It
expects a filename as an argument. If we put a random filename which likely
will not exist, we get the following output:
```
FlagSrvLog : Error opening flag attempt file
FlagSrv Attempt => Items Parsed: 0, Valid Items: 0, Invalid Items: 0
FlagSrv Attempt => --- Flag Not Unlocked, Fix Input and Try Again ---
```

Other commands are interesting as well:

* `fileManager.ShellCommand` expects two arguments: a shell command, and a file
  name where the shell command's output is to be logged. For example, running
  it with parameters `ls` and `out.log` is particularly interesting!
* `fileDownlink.SendFile` expects two arguments: a source filename on the
  satellite, and a destination filename on the simulated ground station. If run
  with parameters `out.log` and `out.log` after running the
  `fileManager.ShellCommand` above, we can get the output of the `ls` command!

At this point, we could list existing files. We saw that a file called
`attempt.txt` exists, with the following contents:
```
1
2
hello
5
11
1000
167
150
21
10103
```

We did some reconnaissance on the satellite:

* We ran `find` to see what is on the filesystem.
* We ran `ps` to see what is running.
* We downloaded the script that starts everything, `/run_space.sh`. It has the
  following contents:
```
echo "Starting spacecraft"
cd /home/space/fsw/
echo "${FLAG}" > /home/space/fsw/.FlagData
unset FLAG
sleep 15
./satellite.exe -a 172.16.238.3 -p 50000
```
* We looked at `satellite.exe`'s environment. No flag there :-(
* `/home/space/fsw/.FlagData` does not exist at the time we issue commands: it
  is removed by `satellite.exe` upon startup.

It seems there are no shortcuts, we'll have to understand this C++ binary...

If `flagSvr` is run with `attempt.txt` as parameter, we get the following
output:

```
FlagSrv Attempt => Loading attempt.txt file for flag enable attempt
FlagSrv Attempt => Items Parsed: 10, Valid Items: 3, Invalid Items: 6
FlagSrv Attempt => --- Flag Not Unlocked, Fix Input and Try Again ---
```

3 valid items!

By reverse engineering `satellite.exe`, we came to understand that it needs to
find 2022 "valid" elements from the file that it receives as first argument.
We thought that numbers satisfying the following constraints
would be valid:

* `number % 3 != 0`
* `number % 5 != 0`
* `number % 7 != 0`
* `number % 6 != 5`
* `number % 6 != 1`

That sounds similar to the infamous "quasi-prime" numbers presented at Black
Hat in 2019! We tried to generate a list of such numbers, but it did not yield
a flag.

At this point, two options were explored in parallel:

* keep staring at that C++ binary which Ghidra does not decompile to something
  that is easy to understand. Reverse Engineering wizards were busy on other
  problems...
* try to understand which of the numbers in the provided `attempt.txt` are
  deemed valid.

And then... we lost track of what we really did. After a lot of trial and
error, we understood that:

* a file containing "2", "5" and "11" has 3 valid items,
* a file containing "2", "5" "11" and "11" has 4 valid items. Whaaat? Can we
  just repeat a valid number??

## Solution

So, we generated a file containing 2022 lines with the number 11 on them, using
this script:
```
for i in seq 1 2022; do echo 11; done > out.txt
```

We uplinked it to `/home/space/fsw/a.txt`, and ran the `flagSvr.FS_FlagEnable`
with `a.txt` as a parameter.

In the logs, we could see a message saying that the flag was unlocked, and that
we could just download `flag.txt`. We downlinked that file to the ground, then
downloaded it. And scored!

## 2nd attempt

To be able to write a proper write-up, we restarted the challenge, uploaded the
file containing 2022 times the number "11", ran `flagSvr.FS_FlagEnable`... and
did not get a flag! Maybe the attempts we had done before sending that file had
done something to `satellite.exe`'s internal state?

We decided that this being a CTF, the only thing that matters is the flag, and
turned our attention to other challenges. We look forward to reading the
challenge's source code!
