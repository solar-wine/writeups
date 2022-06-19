#!/usr/bin/env python3
import pwn
pwn.context.log_level = 'error'

FLAG_END   = '}'
CMD_LAUNCH = 'QEMU_LD_PREFIX=./microblaze-linux LD_LIBRARY_PATH=./microblaze-linux/lib qemu-microblaze ./small_hashes_anyways'
flag       = 'flag{yankee957187romeo3:'

for i in range(0, 87):
    for j in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_':
        p = pwn.process(CMD_LAUNCH, shell=True)
        p.recvline()
        print('sending > ' + flag + j + '.' * (87 - i))
        p.sendline((flag + j + '.' * (87 - i)).encode('utf-8'))
        ret = p.recvline()
        p.close()
        if b'mismatch ' + str(len(flag + j) + 1).encode('utf-8') in ret:
            flag += j
            break

print("\nflag > " + flag + FLAG_END)
