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
    policy = args.policy
    timerange = args.timerange
    target = args.target
    cert = args.certificate
    if action == "mke":
        if not orga:
            raise Exception("No organisation name")

        # Generate key pair for attestation (Cocks IBE scheme)
        cocks_pkg = CocksPKG(128) # The pkg can be viewed as the root private key for attestation
        attest_sk = cocks_pkg
        attest_pk = cocks_pkg.n

        # Generate key pair for signature
        sign_sk, sign_pk = signature.generateSignKeyPair()

        # Locally store keys
        local_save_keys(orga, (attest_sk, attest_pk, sign_sk, sign_pk))

        # # Load keys
        # attest_sk, attest_pk, sign_sk, sign_pk = local_load_keys(orga) 

        # Publish pub keys on chain
        transactor = Transactor()
        sign_pk = pickle.dumps(transactor)
        attest_pk = pickle.dumps(attest_pk)
        orga = pickle.dumps(orga)
        transactor.newEntity(orga, sign_pk, attest_pk)
        
    elif action == "grant":
        if not (issuer and subject and policy and timerange):
            raise Exception("Lack grant args")

        # Essentially an attestation is just a permission delegation certificate
        # An attestation consists of: 
        #   - Cert content
        #       - Policy ([permission]@[uri])
        #       - Time range (as a tuple of Unix timestamps)
        #       - Issuer
        #       - Subject
        #   - A signature over the cert content by issuer
        #   - An issuer attestation private key for the policy (ID)
        # The attestation is encrypted with subject attestation public key + policy ID

        attest = {}
        attest["Cert-content"] = {}
        attest["Cert-content"]["Policy"] = policy
        range_begin = timerange.split(":")[0]
        range_end = timerange.split(":")[0]
        attest["Cert-content"]["Time-range"] = (time.mktime(datetime.datetime.strptime(range_begin, "%d/%m/%Y").timetuple()), 
                                                    time.mktime(datetime.datetime.strptime(range_end, "%d/%m/%Y").timetuple()))
        attest["Cert-content"]["Issuer"] = issuer
        attest["Cert-content"]["Subject"] = subject
        
        # Load issuer keys
        attest_sk, attest_pk, sign_sk, sign_pk = local_load_keys(issuer)
        cert_content_str = json.dumps(attest["Cert-content"])
        attest["Signature"] = signature.sign(cert_content_str, sign_sk)
        policy_sk, policy_ID = attest_sk.extract(policy)
        attest["Issuer-policy-sk"] = policy_sk

        attest = pickle.dumps(attest)

        # Obtain subject attestation public key from the chain
        transactor = Transactor()
        subject_attest_pk = pickle.loads(transactor.getEntityAttestPubKey(pickle.dumps(subject)))
        cocks = Cocks(subject_attest_pk)
        enc_attest = cocks.encrypt(attest, policy_ID) # Note that the policy_ID is the ID (or just a hash) of the policy, and is irrelevant to pkg 

        transactor.uploadCert(pickle.dumps(subject) + pickle.dumps(policy), enc_attest)

        pass

    elif action == "prove":
        if not (subject and policy and target):
            raise Exception("Lack prove args")

        attest_sk, attest_pk, sign_sk, sign_pk = local_load_keys(subject)
        policy_sk, policy_ID = attest_sk.extract(policy)
        policy_pk = attest_sk.n
        cocks = Cocks(policy_pk)

        transactor = Transactor()
        enc_attest = transactor.getCert(pickle.dumps(subject) + pickle.dumps(policy), 0)

        attest_path = []

        while len(enc_attest) != 0:
            attest = cocks.decrypt(enc_attest, policy_sk, policy_ID)
            attest = pickle.loads(attest)
            if not isinstance(attest, dict):
                raise Exception("Error decrypted attestation type")
            if not "Cert-content" in attest:
                raise Exception("Error decrypted attestation dict, no certificate")

            # Verify certificate integrity
            if not verify_cert(attest["Cert-content"], attest["Signature"], attest["Cert-content"]["Issuer"], transactor): 
                raise Exception("Error attestation signature")

            policy_pk = attest.pop("Issuer-policy-sk", None)

            attest_path.push(attest)

            # Obtain encrypted attestation (for the target policy) issued the the issuer
            enc_attest = transactor.getCert(pickle.dumps(attest["Cert-content"]["Issuer"]) + pickle.dumps(policy), 0)   

        # Store attest_path as the proof
        local_save_proof(subject, policy, attest_path)

        pass

    elif action == "verify":
        if not (subject and policy):
            raise Exception("Lack verify args")

        transactor = Transactor()

        # Locally load the proof, assuming that the proof has been recieved and stored secretly
        attest_path = local_load_proof(subject, policy)

        time_range_begin = -1
        time_range_end = 2**64

        for attest in attest_path:
            assert(attest["Cert-content"]["Subject"] == subject, "Error (not matched) subject in attest path")

            # Verify certificate integrity
            if not verify_cert(attest["Cert-content"], attest["Signature"], attest["Cert-content"]["Issuer"], transactor): 
                raise Exception("Error attestation signature")

            # Verify the time range
            if not (attest["Cert-content"]["Time-range"][0] >= time_range_begin and attest["Cert-content"]["Time-range"][1] <= time_range_end):
                raise Exception("Conflicting time range for the policy")

            assert(attest["Cert-content"]["Time-range"][0] < attest["Cert-content"]["Time-range"][1], "Begin of time range larger than the end")         

            time_range_begin = attest["Cert-content"]["Time-range"][0]
            time_range_end = attest["Cert-content"]["Time-range"][1]

            subject = attest["Cert-content"]["Issuer"]

        assert(isAuthority(subject), "The end of the proof path is not an authority")

        pass

    else:
        raise Exception("Unsupported action")
        pass

def isAuthority(entity):
    authority_list = ["admin"]
    return (entity in authority_list)

def verify_cert(cert, sign, signer, transactor):
    cert_str = json.dumps(cert)
    # Obtain the signer public key from the chain
    sign_pk = pickle.loads(transactor.getEntitySignPubKey(pickle.dumps(signer)))
    return signature.verify(cert_str, sign, sign_pk)

def local_save_keys(entityname, key_list):
    # Locally store keys
    with open("local_storage/" + entityname + ".keystore", "wb") as keyfile:
        pickle.dump(key_list, keyfile)    

def local_load_keys(entityname):
    key_list = load_all("local_storage/" + entityname + ".keystore")
    keys = list(key_list)[0]
    return keys

def local_save_proof(entityname, policy, proof):
    # Locally store proof
    with open("local_storage/" + entityname + policy + ".proof", "wb") as pfile:
        pickle.dump(proof, pfile)    

def local_load_proof(entityname, policy):
    proof_list = load_all("local_storage/" + entityname + policy + ".proof")
    proof = list(proof_list)[0]
    return proof

def load_all(filename):
    with open(filename, "rb") as ifile:
        while True:
            try:
                yield pickle.load(ifile)
            except EOFError:
                break

def main():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument("-a", "--action", type=str, help="action oto be performed", choices=["mke", "grant", "prove", "verify"], required=True)

    arg_parser.add_argument("-o", "--organisation", type=str, help="organisation / entity name")
    arg_parser.add_argument("-i", "--issuer", type=str, help="attestation issuer name")
    arg_parser.add_argument("-s", "--subject", type=str, help="attestation subject name")
    arg_parser.add_argument("-p", "--policy", type=str, help="policy string, formatted as [permission]@[uri]")
    arg_parser.add_argument("-r", "--timerange", type=str, help="policy time range, formatted as [begin]:[end], of which the time format is month/day/year")
    arg_parser.add_argument("-t", "--target", type=str, help="permission prove target")

    arg_parser.add_argument("-c", "--proof", type=str, help="proof for permission verification")

    args = arg_parser.parse_args()

    dispatch_args(args)

if __name__ == "__main__":
    main()
    # test_encrypt_decrypt()