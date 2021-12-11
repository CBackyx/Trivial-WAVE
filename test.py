import gmpy2
import argparse
import pickle
# import pytest

from cocks.utils import InvalidIdentityString
from cocks.cocks import CocksPKG, Cocks

def test_encrypt_decrypt():
    m1 = bytes(b"Hello")
    m2 = bytes("Hello world", encoding="utf8")
    # m3 = bytes(12345)
    m4 = bytes(b"aaaaaaaaaaa bbbbbbbbbbbb cccccccccc dddddddddd")
    # m5 = bytes("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.", encoding="utf8")

    cocks_pkg = CocksPKG(128)
    test_id = "test"
    r, a = cocks_pkg.extract(test_id)

    cocks = Cocks(cocks_pkg.n)
    c_list = cocks.encrypt(m1, a)
    xx = pickle.dumps(c_list)
    print(len(xx))
    # print(c_list)
    print(cocks.decrypt(c_list, r, a))
    c_list = cocks.encrypt(m2, a)
    print(cocks.decrypt(c_list, r, a))
    # c_list = cocks.encrypt(m3, a)
    # print(cocks.decrypt(c_list, r, a))
    c_list = cocks.encrypt(m4, a)
    print(cocks.decrypt(c_list, r, a))
    # c_list = cocks.encrypt(m5, a)
    # assert m5 == cocks.decrypt(c_list, r, a)

# test_encrypt_decrypt()

def dispatch_args(args):
    action = args.action
    orga = args.organisation
    issuer = args.issuer
    subject = args.subject
    permission = args.permission
    target = args.target
    cert = args.certificate
    if action == "mke":
        if not orga:
            raise Exception("No organisation name")
        
    elif action == "grant":
        if not (issuer and subject and permission):
            raise Exception("Lack grant args")
        pass

    elif action == "prove":
        if not (subject and permission and target):
            raise Exception("Lack prove args")
        pass

    elif action == "verify":
        if not cert:
            raise Exception("Lack verify args")
        pass

    else:
        raise Exception("Unsupported action")
        pass


def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument("-a", "--action", type=str, help="action oto be performed", choices=["mke", "grant", "prove", "verify"], required=True)

    arg_parser.add_argument("-o", "--organisation", type=str, help="organisation / entity name")
    arg_parser.add_argument("-i", "--issuer", type=str, help="attestation issuer name")
    arg_parser.add_argument("-s", "--subject", type=str, help="attestation subject name")
    arg_parser.add_argument("-p", "--permission", type=str, help="permission string")
    arg_parser.add_argument("-t", "--target", type=str, help="permission prove target")

    arg_parser.add_argument("-c", "--certificate", type=str, help="certificate for permission verification")

    args = arg_parser.parse_args()

    dispatch_args(args)

if __name__ == "__main__":
    # main()
    test_encrypt_decrypt()