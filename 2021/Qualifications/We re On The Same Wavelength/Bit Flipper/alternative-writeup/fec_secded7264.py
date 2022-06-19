# based on : http://www.ecs.umass.edu/ece/koren/FaultTolerantSystems/simulator/Hamming/HammingCodes.html
#
def fec_secded7264_compute_parity(string):
    s = list(map(int, list(''.join(map(lambda x: str(bin(ord(x)))[2:].zfill(8), list(string)))[::-1])))
    P0 = s[0] ^ s[1] ^ s[3] ^ s[4] ^ s[6] ^ s[8] ^ s[10] ^ s[11] ^ s[13] ^ s[15] ^ s[17] ^ s[19] ^ s[21] ^ s[23] ^ s[25] ^ s[26] ^ s[28] ^ s[30] ^ s[32] ^ s[34] ^ s[36] ^ s[38] ^ s[40] ^ s[42] ^ s[44] ^ s[46] ^ s[48] ^ s[50] ^ s[52] ^ s[54] ^ s[56] ^ s[57] ^ s[59] ^ s[61] ^ s[63]
    P1 = s[0] ^ s[2] ^ s[3] ^ s[5] ^ s[6] ^ s[9] ^ s[10] ^ s[12] ^ s[13] ^ s[16] ^ s[17] ^ s[20] ^ s[21] ^ s[24] ^ s[25] ^ s[27] ^ s[28] ^ s[31] ^ s[32] ^ s[35] ^ s[36] ^ s[39] ^ s[40] ^ s[43] ^ s[44] ^ s[47] ^ s[48] ^ s[51] ^ s[52] ^ s[55] ^ s[56] ^ s[58] ^ s[59] ^ s[62] ^ s[63]
    P2 = s[1] ^ s[2] ^ s[3] ^ s[7] ^ s[8] ^ s[9] ^ s[10] ^ s[14] ^ s[15] ^ s[16] ^ s[17] ^ s[22] ^ s[23] ^ s[24] ^ s[25] ^ s[29] ^ s[30] ^ s[31] ^ s[32] ^ s[37] ^ s[38] ^ s[39] ^ s[40] ^ s[45] ^ s[46] ^ s[47] ^ s[48] ^ s[53] ^ s[54] ^ s[55] ^ s[56] ^ s[60] ^ s[61] ^ s[62] ^ s[63]
    P3 = s[4] ^ s[5] ^ s[6] ^ s[7] ^ s[8] ^ s[9] ^ s[10] ^ s[18] ^ s[19] ^ s[20] ^ s[21] ^ s[22] ^ s[23] ^ s[24] ^ s[25] ^ s[33] ^ s[34] ^ s[35] ^ s[36] ^ s[37] ^ s[38] ^ s[39] ^ s[40] ^ s[49] ^ s[50] ^ s[51] ^ s[52] ^ s[53] ^ s[54] ^ s[55] ^ s[56]
    P4 = s[11] ^ s[12] ^ s[13] ^ s[14] ^ s[15] ^ s[16] ^ s[17] ^ s[18] ^ s[19] ^ s[20] ^ s[21] ^ s[22] ^ s[23] ^ s[24] ^ s[25] ^ s[41] ^ s[42] ^ s[43] ^ s[44] ^ s[45] ^ s[46] ^ s[47] ^ s[48] ^ s[49] ^ s[50] ^ s[51] ^ s[52] ^ s[53] ^ s[54] ^ s[55] ^ s[56]
    P5 = s[26] ^ s[27] ^ s[28] ^ s[29] ^ s[30] ^ s[31] ^ s[32] ^ s[33] ^ s[34] ^ s[35] ^ s[36] ^ s[37] ^ s[38] ^ s[39] ^ s[40] ^ s[41] ^ s[42] ^ s[43] ^ s[44] ^ s[45] ^ s[46] ^ s[47] ^ s[48] ^ s[49] ^ s[50] ^ s[51] ^ s[52] ^ s[53] ^ s[54] ^ s[55] ^ s[56]
    P6 = s[57] ^ s[58] ^ s[59] ^ s[60] ^ s[61] ^ s[62] ^ s[63]
    P7 = s[0] ^ s[1] ^ s[2] ^ s[3] ^ s[4] ^ s[5] ^ s[6] ^ s[7] ^ s[8] ^ s[9] ^ s[10] ^ s[11] ^ s[12] ^ s[13] ^ s[14] ^ s[15] ^ s[16] ^ s[17] ^ s[18] ^ s[19] ^ s[20] ^ s[21] ^ s[22] ^ s[23] ^ s[24] ^ s[25] ^ s[26] ^ s[27] ^ s[28] ^ s[29] ^ s[30] ^ s[31] ^ s[32] ^ s[33] ^ s[34] ^ s[35] ^ s[36] ^ s[37] ^ s[38] ^ s[39] ^ s[40] ^ s[41] ^ s[42] ^ s[43] ^ s[44] ^ s[45] ^ s[46] ^ s[47] ^ s[48] ^ s[49] ^ s[50] ^ s[51] ^ s[52] ^ s[53] ^ s[54] ^ s[55] ^ s[56] ^ s[57] ^ s[58] ^ s[59] ^ s[60] ^ s[61] ^ s[62] ^ s[63] ^ P0 ^ P1 ^ P2 ^ P3 ^ P4 ^ P5 ^ P6
    parity = f'{int("".join(map(str, [P0, P1, P2, P3, P4, P5, P6, P7]))[::-1], 2):02x}'

    return bytes.fromhex(parity)

def fec_secded7264_encode(string):
    encoded = b''
    while (len(string) >= 8):
        block = string[0:8]
        string = string[8:]
        parity = fec_secded7264_compute_parity(block)
        encoded += block.encode('utf-8') + parity

    if (len(string)):
        block = string.ljust(8, "\x00")
        parity = fec_secded7264_compute_parity(block)
        encoded += string.encode('utf-8') + parity
    
    return encoded

def fec_secded7264_decode_lazy(string):
    decoded = b''
    while (len(string) >= 9):
        block = string[0:8]
        string = string[9:]
        decoded += block

    if (len(string)):
        block = string[:-1]
        decoded += block

    return decoded
