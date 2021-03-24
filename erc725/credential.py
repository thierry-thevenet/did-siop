
from authlib.jose import JsonWebSignature
import requests
import json
from datetime import datetime


def verify_credential(signed_credential, did) :
    """
    Verify credential signed with RSA key of the DID
    @parma signed_credential as a dict
    @param did as a str
    return bool
    """
    read = requests.get('https://talao.co/resolver?did=' + did)
    for Key in read.json()['publicKey'] :
        if Key.get('id') == did + "#secondary" :
            public_key = Key['publicKeyPem']
            break
    jws = JsonWebSignature()
    try :
        jws.deserialize_compact(signed_credential['proof']['jws'], public_key)
    except :
        return False
    return True



def sign_credential(credential, key) :
    """
    Sign credential with RSA key of the did, add the signature as linked data JSONLD
    @parma credential as a dict
    #param key a string PEM private RSA key
    return signed credential as a dict
    """
    payload = json.dumps(credential)
    credential_jws = JsonWebSignature(algorithms=['RS256'])
    protected = {'alg': 'RS256'}
    signature = credential_jws.serialize_compact(protected, payload, key.encode()).decode()
    credential["proof"] = {"type": "RsaSignature2018",
                "created": datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                "proofPurpose": "assertionMethod",
                "verificationMethod": "https://talao.readthedocs.io/en/latest/",
                "jws" : signature
             }
    return credential


if __name__ == '__main__':

    test_did = "did:talo:talaonet:c5C1B070b46138AC3079cD9Bce10010d6e1fCD8D" # correct did
    #test_did = "did:talao:talaonet:81d8800eDC8f309ccb21472d429e039E0d9C79bB" #  wrong did

    test_rsa_key =""


    unsigned_credential = {"test" : 5}
    signed_credential = sign_credential(unsigned_credential, test_rsa_key)
    print(signed_credential, type(signed_credential))
    print(verify_credential(signed_credential, test_did))
