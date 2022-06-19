from fec_secded7264 import *

origin = "eturn 0\n"
wanted = "eturn 1\n"

print(origin.encode('utf-8'))
print(b"parity: " + fec_secded7264_compute_parity(origin))
print(wanted.encode('utf-8'))
print(b"parity: " + fec_secded7264_compute_parity(wanted))
