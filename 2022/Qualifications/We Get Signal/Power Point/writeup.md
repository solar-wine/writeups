# HACK-A-SAT 3: Power Point

* **Category**: We Get Signal
* **Points**: 165
* **Solves**: 19
* **Description:**

> Break out Microsoft Office because its time to make some slides… just kidding!

> There is a satellite out there transmitting a flag. You are on a moving platform and you don't know how you will be moving or where the transmitter is or how the transmitter is moving. Luckily you have a steerable antenna! To get the flag:
>
> 1. Find the transmitter by steering the antenna.
> 2. Keep the antenna pointed at the transmitter and try to maximize signal power.
> 3. Decode the samples coming in from your receiver.
>
> Your co-worker told you they think the satellites is "North-ish and sort of close to the horizon"

> Send az, el commands to the antenna; an antenna command is formatted as a string for example if az=77.1 and el=73.2
>
> `send: 77.10,22.2\n`
>
> Please send one command at a time.
>
> After you send a command the receiver will reply with a fixed number of IQ samples via TCP.

## Requirements

This write-up will use:

- Python3
- Numpy: <https://numpy.org/install/>

## Write-up

_Write-up by Solar Wine team_

First, connect to the challenge via nc.
This is what the service asks us when we provide it with our team ticket:

```shell
$ echo 'ticket{juliet365159quebec3:GEwdB3WJC6Lzj_rW7wn3Sine6taWUC79-XDO_MRl8oyg3MNSlY-_c5pgmM6bqKTlSw}' | nc power_point.satellitesabove.me 5100
Ticket please:
Keep the signal power high if to get the flag



Antenna pointing TCP server accepts commands at 44.193.213.139:12688
Sample TCP server will provide samples at 44.193.213.139:12689
The flag begins at byte: 7200
Sample server: Waiting for client connection
```

After finding a good start position for the antenna we tried our best to keep it in the right direction.
Unfortunately we had some bad signal that we fixed manually.
To keep the antenna pointing in the right direction we analyzed the strength of the signal:

```python
## calculate strength of signal
def getSigStrength(buf):
    dt = np.dtype(np.float32)
    dt = dt.newbyteorder('<')

    data = np.frombuffer(buf, dtype=dt)
    IQ = data[0::2] +1j* data[1::2]
    IQ = IQ[:1024*8]

    s = 100e2
    N = 1024
    PSD = (np.abs(np.fft.fft(IQ))/N)**2
    PSD_log = 10.0*np.log10(PSD)
    PSD_shifted = np.fft.fftshift(PSD_log)
    IQ = IQ * np.hamming(len(IQ))

    Fs = 100e3
    center_freq = 0                      # frequency we tuned our SDR to
    f = np.arange(Fs/-2.0, Fs/2.0, Fs/N) # start, stop, step.  centered around 0 Hz
    f += center_freq                     # now add center frequency

    sig_freq=f[np.argmax(PSD_shifted)]
    mx = np.max(PSD_shifted)

    return (mx,sig_freq)
```

Using the signal strength, we first scan around the estimated position ( around the north and close to horizon).
This provides a good starting point, at az=8.0°,el=19.0°; with a pretty large margin.

By analysing the signal using GNU Radio (waterfall, amplitude over time, phase over time and constellation diagram), we can identify the modulation and the "baudrate" : QPSK is used with a 2-bit symbol sent every 10 points. Nevertheless, the symbol encoding is still not know yet.

From the console, we know that the flag is sent at the offset 7200. Nevertheless, since the satellite is moving, we need to implement a tracking mechanism to get more data.

The implemented tracking algorithm move 2.0° on both direction to update the receiving point using the maximum strength value. There is some data loss, but prior the flag.

```python
bestPoint=(80,190)
while True:
    bestSig = 0
    for azo in range(-1,2,1):
        (az,el) = (bestPoint[0]+(azo*20), bestPoint[1])
        buf = moveAntenna(az, el)

        if(buf == None):
            print("%04x %.1f,%.1f bad signal" %(N, az,el))
            continue

        (snr,strength,sig_freq) = getSigStrength(buf)
        if(strength > bestSig):
            bestSig = strength
            bestPoint = (az,el)

        dec = decode(buf)
        
        print("%04x %.1f,%.1f %s (%.1f)" % (N, az,el, dec, strength))

    for elo in range(-1,2,1):
        (az,el) = (bestPoint[0], bestPoint[1]+(elo*20))
        buf = moveAntenna(az, el)

        if(buf == None):
            print("%04x %.1f,%.1f bad signal" %(N, az,el))
            continue

        (snr,strength,sig_freq) = getSigStrength(buf)
        if(strength > bestSig):
            bestSig = strength
            bestPoint = (az,el)

        dec = decode(buf)
        
        print("%04x %.1f,%.1f %s (%.1f)" % (N, az,el, dec, strength))
```

Next, we retrieved data, decoded it, and reversed the encoding to finally get the flag.

Running the python script, we get:
```shell
$ python solver.py
b'Sending ... > ticket{juliet365159quebec3:GEwdB3WJC6Lzj_rW7wn3Sine6taWUC79-XDO_MRl8oyg3MNSlY-_c5pgmM6bqKTlSw}'
b'44.193.213.139' b'20611'
b'44.193.213.139' b'20610'
7200
b'Sample server: Waiting for client connection\nSample Server: Client connected\nAntenna pointing server: Waiting for client to connect\nAntenna pointing server: Client connected\nPress Enter to quit:'
0000 > [60.0, 190.0] (29.9)
001c > [60.0, 190.0] (30.3)
0038 > [80.0, 190.0] (37.9)
...
HackASat\nHackASat\nHackASat\nHackASat\nHackASat\nHackASat\nHackASat\nHackASat\nHackASat\nHackASat\nHackASat\nHackASat\nHackASat\nHackASat\nflag{juliet365159quebec3:GHsLDtL_uXX91-6xVhUQGzZq9G4SbtJrjvYIc3Y_r-ydrIv7B8myunQwW5-B1l-tzACqnBOgWyZ8UlMzWzp1QMc}\n
```

