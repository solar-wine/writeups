import numpy as np
import time
import binascii
from socket import socket

TICKET = b'ticket{juliet365159quebec3:GEwdB3WJC6Lzj_rW7wn3Sine6taWUC79-XDO_MRl8oyg3MNSlY-_c5pgmM6bqKTlSw}'
REMOTE = ('power_point.satellitesabove.me',5100)

## just a recv and wait a string
def waitfor(s, x):
    buf = b""
    while True:
        buf += s.recv(1)
        if x in buf:
            return buf

## Send a command, check if tracking is lost on d, return None if tracking is lost or sample if not
def command(az, el):
    cmd.send(b"%.1f,%.1f\n" % (az/10.0, el/10.0))
    buf = waitfor(d,b"TCP/IP")

    s = b""
    while(len(s) < 8192):
        s += samp.recv(8192)

    if b"Tracking lost" in buf:
        return None
    return s

## decode rawdata
def decode(buf, bitLen=10):
    dt = np.dtype(np.float32)
    dt = dt.newbyteorder('<')

    data = np.frombuffer(buf, dtype=dt)
    IQ = data[0::2] +1j* data[1::2]

    rawdata = np.angle(IQ)
    normalizeddata = rawdata
    normalizeddata /= (np.max(rawdata)-np.min(rawdata))/2

    return normalizeddata.tolist()

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

    mn=0
    for i in range(len(PSD_shifted)):
        if f[i] == sig_freq:
            continue
        mn += PSD_shifted[i]

    mn /= len(PSD_shifted)-1
    snr = mx-mn

    return (snr,mx,sig_freq)

## fix manually some bad signal
def fixBadSignal(N, az, el):
    if ("%04x" % (N)) == "0738" or ("%04x" % (N)) == "0754":
        return (80, 190)

    if ("%04x" % (N)) == "09d8":
        return (100, 170)

    if ("%04x" % (N)) == "0bd0":
        return (120, 150)

    if ("%04x" % (N)) == "0dc8":
        return (140, 130)

    if ("%04x" % (N)) == "0fc0" or ("%04x" % (N)) == "0fdc":
        return (160, 130)

    if ("%04x" % (N)) == "1068":
        return (160, 110)

    return (az, el)

## convert normalized datas
def convertDatas(normalizeddatas):
    data = ''
    while len(normalizeddatas) >= 10:       # each value is repeated 10 times
        if(normalizeddatas[5] > 0.5):       # random, take the 5th value
            data += '10'                   # we found this decoding because offset 7200 must start with 'flag{'
        elif(normalizeddatas[5] > 0):
            data += '11'                   # we found this decoding because offset 7200 must start with 'flag{'
        elif(normalizeddatas[5] > -0.5):
            data += '01'                   # we found this decoding because offset 7200 must start with 'flag{'
        else:
            data += '00'                   # we found this decoding because offset 7200 must start with 'flag{'
        
        del normalizeddatas[0:10]           # delete converted datas from array
    
    return (normalizeddatas, data)

## re order datas
def orderingDatas(datas):
    ordered = b''
    while len(datas) >= 8:
        n = int('0b' + datas[6:8] + datas[4:6] + datas[2:4] + datas[0:2], 2)
        ordered += binascii.unhexlify('%02x' % n)
        datas = datas.replace(datas[0:8], '', 1)
    
    return ordered

## Initial connections            
d=socket()
d.connect(REMOTE)

## Send ticket
waitfor(d, b"Ticket please:")
print(b'Sending ... > ' + TICKET)
d.send(TICKET+b"\n")

## Retrieve challenge infos
waitfor(d, b"commands at ")
caddr = waitfor(d, b"\n")
waitfor(d, b"samples at ")
saddr = waitfor(d, b"\n")
waitfor(d, b"at byte: ")
sofs = waitfor(d, b"\n")

## flag offset
OFFSET = int(sofs.strip())
cip,cport = caddr.strip().split(b":")
sip,sport = saddr.strip().split(b":")
print(sip, sport)
print(cip, cport)
print(OFFSET)

## connect to remote tcp server
cmd = socket()
samp = socket()
time.sleep(1)
samp.connect((sip,int(sport)))
time.sleep(1)
cmd.connect((cip,int(cport)))
print(waitfor(d,b"quit:"))

## initialize an (az, el) that works with our challenge
bestCandidate=(80,190)
bestSig = 0
N = 0
normalizeddatas = []
datas = ''

while True:
    bestSig = 0
    for azo in range(-1,2,1):
        (az, el) = (bestCandidate[0]+(azo*20), bestCandidate[1])
        (az, el) = fixBadSignal(N, az, el)

        buf = command(az, el)   # retrieve datas
        if(buf == None):        # should not happen
            print("%04x %.1f,%.1f bad signal" %(N, az,el))
            N += 28
            continue

        # calculate strength of signal and update bestCandidate
        (snr,strength,sig_freq) = getSigStrength(buf)
        if(strength > bestSig):
            bestSig = strength
            bestCandidate = (az,el)

        normalizeddatas += decode(buf)                          # concatenate past normalizeddatas with new one
        (normalizeddatas, data) = convertDatas(normalizeddatas) # convert 10 datas by 10 datas and keep the rest
        datas += data                                           # concatenate past datas with new one

        print("%04x > [%.1f, %.1f] (%.1f)" % (N, az, el, strength))
        N += 28 # just an increment to follow/debug each tick and to manually fix some bad signals


    for elo in range(-1,2,1):
        (az, el) = (bestCandidate[0], bestCandidate[1]+(elo*20))
        (az, el) = fixBadSignal(N, az, el)

        buf = command(az, el)   # retrieve datas
        if(buf == None):        # should not happen
            print("%04x %.1f,%.1f bad signal" %(N, az,el))
            N += 28
            continue

        # calculate strength of signal and update bestCandidate
        (snr,strength,sig_freq) = getSigStrength(buf)
        if(strength > bestSig):
            bestSig = strength
            bestCandidate = (az,el)

        normalizeddatas += decode(buf)                          # concatenate past normalizeddatas with new one
        (normalizeddatas, data) = convertDatas(normalizeddatas) # convert 10 datas by 10 datas and keep the rest
        datas += data                                           # concatenate past datas with new one

        print("%04x > [%.1f, %.1f] (%.1f)" % (N, az, el, strength))
        N += 28 # just an increment to follow/debug each tick and to manually fix some bad signals


    if(N > (0x1f00)):
        print(orderingDatas(datas))
        break
