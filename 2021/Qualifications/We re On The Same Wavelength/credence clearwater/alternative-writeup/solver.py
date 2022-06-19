from textwrap import wrap

f = open('iqdata.txt', 'rb')
samples = f.readlines()
bin = ''
n = 0

for iqstr in samples:
    if n % 4 == 0: # period is 4
        bit = '1'
        if iqstr[0] == ord('-'):
            bit = '0'

        if b'+' in iqstr:
            bit += '1'
        else:
            bit += '0'

        # transform pair of bits
        if bit == '00':
            bit = '01'
        elif bit == '01':
            bit = '00'

        bin += bit
    n += 1

octets = wrap(bin, 8)
result = ''
for octet in octets:
	result += chr(int(octet, 2))

print(result)
