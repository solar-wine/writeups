import numpy as np

a = [0,0,1]
b = [ 0.14129425, -0.98905974,  0.04238827]

axis = np.cross(a, b)
axis /= np.linalg.norm(axis)
arc = np.dot(a, b)

qr = np.sqrt((1+arc)/2)
qi = np.sqrt((1-arc)/2)*axis

for e in qi:
    print(e)
print(qr)

"flag{papa270505oscar2:GCiJZjD3KHSws0niO_Kp7nGGsp4MpXnlzH4Z5C-TP0mKP-uYZtsJtTFXQkiklRzfOC_lU0AWRTq7LAlTjAohwEU}"
