import pwn

TICKET = b'ticket{oscar27279delta2:GAhUCEqGmxSr_PZM4S1JG5EX9xWaMMSf19E5cMjpiIdw4KmnYxEQH9CCeLutSdJsgg}'

def ticket():
  p.recvuntil(b'Ticket please:')
  p.sendline(TICKET)

def get_challenge():
  p.recvuntil(b'Bits to transmit: ')
  bits = p.recvuntil(b'\n').decode('utf-8')
  p.recvuntil(b'Input samples: ')
  print('received < ' + bits)
  return bits

# just replace 0 by -1.0 and 1 by 1.0
def get_solution(challenge):
  bits = challenge.replace(' ', '')
  bits = bits.replace('0', '-7.0 ')
  bits = bits.replace('1', '1.0 ')
  bits = bits.replace('7', '1')
  bits = bits.strip()
  return bits

p = pwn.remote('unique-permit.satellitesabove.me', 5006)
ticket()
challenge = get_challenge()
solution = get_solution(challenge)
print('sending > ' + solution + '\n')
p.sendline(solution)
print(p.recv().decode('utf-8')) # get the flag

p.close()
