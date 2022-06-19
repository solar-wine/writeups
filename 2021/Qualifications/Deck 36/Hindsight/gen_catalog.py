from math import *
from catalog import *

ROUND = 6

def calc_dist(s1, s2):
  return sqrt((s1[0]-s2[0])**2 + (s1[1]-s2[1])**2 + (s1[2]-s2[2])**2)

i = 0
new_cat = []
for s1 in catalog:
  new_cat.append([s1,[]])
  for s2 in catalog:
    d = round(calc_dist(s1,s2), ROUND)
    new_cat[i][1].append(d)
  i = i + 1

print(new_cat)
