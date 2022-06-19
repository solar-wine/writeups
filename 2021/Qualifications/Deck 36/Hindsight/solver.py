from math import *
from new_catalog import *
import pwn
import collections, numpy

ROUND = 6
TICKET = b'ticket{echo28410zulu2:GKMF-DGuNjMOrawFCB621Jd7rRgcEysXbmmdqPz8mZTTbjhJZr7O0-roXrrdMNBcUA}'
lines = []

def ticket():
  p.recvuntil(b'Ticket please:')
  p.sendline(TICKET)

def pass_stage(sol):
  p.sendline(sol)
  p.recvuntil(b'Left...') 

def nextr():
  rez = p.recvuntil(b'(Comma Delimited):').split(b'\n')
  lines = []
  for line in rez:
    if b"," in line:
      r = line.split(b',\t')
      x = float(r[0])
      y = float(r[1])
      z = float(r[2])
      lines.append([x, y, z])
  return lines

# only use X,Y this year
def calcdist(s1, s2):
  return sqrt((s1[0]-s2[0])**2 + (s1[1]-s2[1])**2)

# make the catalog of distances from stars provided by the service
def make_d(stars):
  i = 0
  newstars = []
  for s1 in stars:
    newstars.append([s1,[]])
    for s2 in stars:
      d = round(calcdist(s1,s2), ROUND)
      if d != 0:
        newstars[i][1].append(d)

    i = i + 1
  return newstars

def get_sol(stars):
  stars_id = []
  # iterate over 30 privoded stars, because some of them won't match
  for i in range(30):
    findings = []
    f1 = stars[i]
  
    for d1 in f1[1]:
      for s in catalog:
        for ss in s[1]:
          if abs(d1 - ss) < 0.0005: # allowed error (selected randomly after few tries)
            findings.append(s[1].index(ss))

    a = numpy.array(findings)
    c = collections.Counter(a)

    bests = c.most_common(2)
    # sometimes two (or more) stars match a lot
    # only keep a star if it is the only one that match
    if bests[0][1] - bests[1][1] > 4:
      id = str(bests[0][0])
      stars_id.append(id)
      print('found: ' + id)

  return numpy.unique(stars_id)

# stars we found during the quals
# made manually after each stage
#solutions = [
#  ['180', '25',' 277', '311', '479', '51', '693', '852', '944', '979'],
#  ['136', '213', '458', '563', '575', '627', '649', '659', '699', '703', '874', '1014', '1086', '1255'],
#  ['51', '235', '277', '495', '715', '775', '1286', '1479', '1505', '1620', '1701'],
#  ['53', '213', '416', '627', '649', '682', '705', '914', '947', '1086'],
#  ['132', '369', '525', '686', '692', '769', '1145', '1242', '1253', '1402', '1412'],
#]

solutions = []
for i in range(6):
  p = pwn.remote('early-motive.satellitesabove.me', 5002)
  ticket()

  for s in solutions:
    print("sending > " + ','.join(s))
    p.sendline(','.join(s))
    p.recvuntil(b'Left...')

  if i == 5:
    print(p.recvuntil(b'}\n')) # get flag
    p.close()
    exit(0)

  stars = nextr()
  stars = make_d(stars)
  s = get_sol(stars)
  solutions.append(s)
  p.close()
