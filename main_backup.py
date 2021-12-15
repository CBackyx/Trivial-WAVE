import gmpy2
import argparse
import pickle
import signature
from transaction import Transactor
# import pytest

from cocks.utils import InvalidIdentityString
from cocks.cocks import CocksPKG, Cocks

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import prime192v2
from charm.schemes.pkenc.pkenc_cs98 import CS98
from charm.core.engine.util import objectToBytes,bytesToObject

# mg07a
from fibre.pre_mg07a_jet import PreGA

import time
import datetime

import json

def test_encrypt_decrypt():
    return
    
# test_encrypt_decrypt()

def dispatch_args(args):
    action = args.action
    orga = args.organisation
    issuer = args.issuer
    subject = args.subject
    policy = args.policy
    timerange = args.timerange
    target = args.target

    if action == "mke":
        if not orga:
            raise Exception("No organisation name")

        # Generate key pair for attestation (FIBRE IBE scheme)
        pre, group = getPreAndPairGroup()

        (mk, params) = pre.setup()

        attest_sk = mk
        attest_pk = params

        # Generate key pair for signature
        sign_sk, sign_pk = signature.generateSignKeyPair()

        # Locally store keys
        local_save_keys(orga, (attest_sk, attest_pk, sign_sk, sign_pk), group)

        # # Load keys
        # attest_sk, attest_pk, sign_sk, sign_pk = local_load_keys(orga) 

        # Publish pub keys on chain
        transactor = Transactor()
        sign_pk = pickle.dumps(sign_pk)
        print(sign_pk)
        attest_pk = objectToBytes(attest_pk, group)
        print(attest_pk)
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
        range_end = timerange.split(":")[1]
        attest["Cert-content"]["Time-range"] = (time.mktime(datetime.datetime.strptime(range_begin, "%d/%m/%Y").timetuple()), 
                                                    time.mktime(datetime.datetime.strptime(range_end, "%d/%m/%Y").timetuple()))
        attest["Cert-content"]["Issuer"] = issuer
        attest["Cert-content"]["Subject"] = subject
        
        pre, group = getPreAndPairGroup()

        # Load issuer keys
        attest_sk, attest_pk, sign_sk, sign_pk = local_load_keys(issuer, group)
        cert_content_str = json.dumps(attest["Cert-content"])
        print(cert_content_str)
        attest["Signature"] = signature.sign(cert_content_str, sign_sk)

        policy_ID = policy
        policy_sk = pre.keyGen(attest_sk, policy_ID)
        attest["Issuer-policy-sk"] = objectToBytes(policy_sk, group)

        attest = pickle.dumps(attest)

        print(len(attest))

        # Obtain subject attestation public key from the chain
        transactor = Transactor()
        subject_attest_pk = bytesToObject(transactor.getEntityAttestPubKey(pickle.dumps(subject)), group)
        print(subject_attest_pk)
        enc_attest = pre.encrypt_jet(subject_attest_pk, policy_ID, attest) # Note that the policy_ID is the ID (or just a hash) of the policy, and is irrelevant to pkg 
        
        # print(attest)
        # print(enc_attest)

        # attest_sk, attest_pk, sign_sk, sign_pk = local_load_keys(subject, group)
        # policy_sk = pre.keyGen(attest_sk, policy_ID)
        # attest = pre.decrypt_jet(subject_attest_pk, policy_sk, enc_attest)
        
        transactor.uploadCert(pickle.dumps(subject) + pickle.dumps(policy), objectToBytes(enc_attest, group))

        pass

    elif action == "prove":
        if not (subject and policy and target):
            raise Exception("Lack prove args")

        pre, group = getPreAndPairGroup()

        attest_sk, attest_pk, sign_sk, sign_pk = local_load_keys(subject, group)
        policy_ID = policy
        policy_sk = pre.keyGen(attest_sk, policy_ID)
        policy_pk = attest_pk

        transactor = Transactor()
        enc_attest = transactor.getCert(pickle.dumps(subject) + pickle.dumps(policy), 0)

        attest_path = []

        while len(enc_attest) != 0:
            attest = pre.decrypt_jet(attest_pk, policy_sk, bytesToObject(enc_attest, group))
            attest = pickle.loads(attest)
            if not isinstance(attest, dict):
                raise Exception("Error decrypted attestation type")
            if not "Cert-content" in attest:
                raise Exception("Error decrypted attestation dict, no certificate")

            # Verify certificate integrity
            if not verify_cert(attest["Cert-content"], attest["Signature"], attest["Cert-content"]["Issuer"], transactor): 
                raise Exception("Error attestation signature")

            policy_sk = bytesToObject(attest.pop("Issuer-policy-sk", None), group)

            print(attest)
            attest_path.append(attest)

            # Obtain encrypted attestation (for the target policy) issued the the issuer
            enc_attest = transactor.getCert(pickle.dumps(attest["Cert-content"]["Issuer"]) + pickle.dumps(policy), 0)   

        # Store attest_path as the proof
        print(attest_path)
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

        print(attest_path)

        for attest in attest_path:
            # print("hahahahha")
            assert attest["Cert-content"]["Subject"] == subject, "Error (not matched) subject in attest path"

            # Verify certificate integrity and validity
            if not verify_cert(attest["Cert-content"], attest["Signature"], attest["Cert-content"]["Issuer"], transactor): 
                raise Exception("Error attestation signature")

            # Verify the time range
            if not (attest["Cert-content"]["Time-range"][0] >= time_range_begin and attest["Cert-content"]["Time-range"][1] <= time_range_end):
                raise Exception("Conflicting time range for the policy")

            assert attest["Cert-content"]["Time-range"][0] < attest["Cert-content"]["Time-range"][1] \
                            ,"Begin of time range larger than the end"       

            time_range_begin = attest["Cert-content"]["Time-range"][0]
            time_range_end = attest["Cert-content"]["Time-range"][1]

            subject = attest["Cert-content"]["Issuer"]
            # print("hahahahha")

        print(subject)

        assert isAuthority(subject), "The end of the proof path is not an authority"

        pass

    elif action == "revoke":
        if not (issuer and subject and policy and timerange):
            raise Exception("Lack grant args")

        pre, group = getPreAndPairGroup()

        attest = {}
        attest["Cert-content"] = {}
        attest["Cert-content"]["Policy"] = policy
        range_begin = timerange.split(":")[0]
        range_end = timerange.split(":")[1]
        attest["Cert-content"]["Time-range"] = (time.mktime(datetime.datetime.strptime(range_begin, "%d/%m/%Y").timetuple()), 
                                                    time.mktime(datetime.datetime.strptime(range_end, "%d/%m/%Y").timetuple()))
        attest["Cert-content"]["Issuer"] = issuer
        attest["Cert-content"]["Subject"] = subject
        
        # Load issuer keys
        attest_sk, attest_pk, sign_sk, sign_pk = local_load_keys(issuer, group)
        cert_content_str = json.dumps(attest["Cert-content"])
        
        # Put revoke signature
        transactor = Transactor()
        transactor.putRevokeSign(pickle.dumps(signature.sign(cert_content_str, sign_sk)), pickle.dumps(signature.sign(cert_content_str + ":revoked", sign_sk))) 
        print(cert_content_str)
        print(signature.sign(cert_content_str, sign_sk)) 
                    

    else:
        raise Exception("Unsupported action")
        pass


def getPreAndPairGroup():
    group = PairingGroup('SS512', secparam=2024)
    groupcs98 = ECGroup(prime192v2)

    pkenc = CS98(groupcs98)
    pre = PreGA(group, pkenc)

    return (pre, group)

def isAuthority(entity):
    authority_list = ["admin"]
    return (entity in authority_list)

def verify_cert(cert, sign, signer, transactor):
    cert_str = json.dumps(cert)
    # Obtain the signer public key from the chain
    sign_pk = pickle.loads(transactor.getEntitySignPubKey(pickle.dumps(signer)))

    # Check if revoked or not
    revokeSign = transactor.getRevokeSign(pickle.dumps(sign))
    if (revokeSign is not None) and len(revokeSign) != 0:
        if signature.verify(cert_str + ":revoked", pickle.loads(revokeSign), sign_pk):
            raise Exception("Revoked attestation")

    return signature.verify(cert_str, sign, sign_pk)

def local_save_keys(entityname, key_list, group):
    key_list = list(key_list)
    key_list[0] = objectToBytes(key_list[0], group)
    key_list[1] = objectToBytes(key_list[1], group)
    # Locally store keys
    with open("local_storage/" + entityname + ".keystore", "wb") as keyfile:
        pickle.dump(key_list, keyfile)    

def local_load_keys(entityname, group):
    key_list = load_all("local_storage/" + entityname + ".keystore")
    keys = list(key_list)[0]
    keys[0] = bytesToObject(keys[0], group)
    keys[1] = bytesToObject(keys[1], group)
    keys = tuple(keys)
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

    arg_parser.add_argument("-a", "--action", type=str, help="action oto be performed", choices=["mke", "grant", "prove", "verify", "revoke"], required=True)

    arg_parser.add_argument("-o", "--organisation", type=str, help="organisation / entity name")
    arg_parser.add_argument("-i", "--issuer", type=str, help="attestation issuer name")
    arg_parser.add_argument("-s", "--subject", type=str, help="attestation subject name")
    arg_parser.add_argument("-p", "--policy", type=str, help="policy string, formatted as [permission]@[uri]")
    arg_parser.add_argument("-r", "--timerange", type=str, help="policy time range, formatted as [begin]:[end], of which the time format is day/month/year")
    arg_parser.add_argument("-t", "--target", type=str, help="permission prove target")

    arg_parser.add_argument("-c", "--proof", type=str, help="proof for permission verification")

    args = arg_parser.parse_args()

    dispatch_args(args)

if __name__ == "__main__":
    main()
    # test_encrypt_decrypt()