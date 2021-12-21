#!/usr/bin/python3

# Procedures:
# C1 = IBE(m, ID1)
# rk12 = genRK(sk1, ID2)
# C2 = RE(C1, rk12)
# m = IBD(C2, sk2)

import time

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import prime192v2
from charm.schemes.pkenc.pkenc_cs98 import CS98

# mg07a
from pre_mg07a_jet import PreGA

from fibre import fibre2

#

group = PairingGroup('SS512', secparam=2024)
groupcs98 = ECGroup(prime192v2)

pkenc = CS98(groupcs98)
pre = PreGA(group, pkenc)


# PRE SETUP
(mk, params) = pre.setup()
print(params)

ID1 = "Harry_Potter@gmail.com"
ID2 = "Jet_Luo@gmail.com"

# Bytes message
msg = 'ab' * 330
m = msg.encode('utf-8')

# Run counts
count = 1

#m = group.random(GT)    
while count>=1:
    
    print("Run count = ", count)
    # Random message
    fibre2(pre, ID1, ID2, m, mk, params, group)
    count -= 1



    

