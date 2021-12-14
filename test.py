import gmpy2
import argparse
import pickle
import signature
from transaction import Transactor
# import pytest

from cocks.utils import InvalidIdentityString
from cocks.cocks import CocksPKG, Cocks

import time
import datetime

import json

def test_encrypt_decrypt():
    m1 = bytes(b"Hello")
    m2 = bytes("Hello world", encoding="utf8")
    # m3 = bytes(12345)
    m4 = bytes(b"aaaaaaaaaaa bbbbbbbbbbbb cccccccccc dddddddddd")
    # m5 = bytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.", encoding="utf8")

    cocks_pkg = CocksPKG(128)
    test_id = "test"
    r, a = cocks_pkg.extract(test_id)
    print(r,a)

    cocks_pkg = CocksPKG(128)
    test_id = "test"
    r, a = cocks_pkg.extract(test_id)
    print(r,a)

    return

# test_encrypt_decrypt()

def test_transaction():
    transactor = Transactor()
    entity = "admin"
    print(transactor.getRevokeSign(pickle.dumps(entity)))
    # print(transactor.getEntitySignStatus(pickle.dumps(entity)))

if __name__ == "__main__":
    test_transaction()
    # test_encrypt_decrypt()