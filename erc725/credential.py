
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

    test_rsa_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA16beMp//Gb7xuPpcIp9GWxEQLCwleBfHNHs4xG5w/h3njYF4
QdF9o/NA5neTzAhO+ks1SzhpmIx4tTM56hfdiU6st4TP2nPbeUITdPK3i7rJeTYt
AfZV5MNdBp0r0rIIf+KhjN24MCDUQJrlfbWQuCmy4E9Tv5kSANv+Ls3e+Yiw08CA
VGOv5mN/81FRf9Dovg6r91ftepOow2MwfxiX3llaf9hCxdOr8591L82d+7HRGlA1
mCyR0/tsWtLa9XCj4KdINMhErYZH+oeVSq901AOHvZ6GumaFUbkGOVIunMrfhNSO
bUmaUqWXoKzJCV0EAtlFYVF3XgDeTGMPagE0pwIDAQABAoIBADrZfkSJdge0HGny
5IbMOVprryKmz3jU4FdZkxXD39DxHzn2DXfEsAk4PktGcY5Z7BeQw5Pp6qMnHl+w
gYr5BUtNrYONWl2OhWOzXPTqsZ0PlaCe4Kxq6Wi6yZ2e8ZEXZYtksNpsvTFhHBsf
SiZCkKI5OufMrhmYr5mNb3GdW85zdu6SGr+8XMpwVPnmVw8b9r5lVX57nDMVFQzm
vpauhszth5TWQx0V8FhWQQjtR604Sx3urrM5lzk7JtNACa3Sas0T0tpinKObCcFX
j++ilKkshVMShOZcdT/dZuUkhUSB+qx/ra5+yR4HXOpWwWoeKN6LthmOFDcpsYN6
+J3pMeUCgYEA3B6j7V6cQrFQ6qkfwYTktDuEvxBpqdJE2atRkIb6nFlKsnLD5i0r
8QRt8DpQqauhIClHFp0ppCXAG4ti5m3SV+GUZzhabMTzagpvKgIw+ddujXkQwiUC
kGyNll2nBOaaENKmnQpS3IhIa3MO1+RkmDKrYfHWVocvPXcXYp7iVasCgYEA+s3J
3rSMVnU70OlpYXeiOZYVYb5Iz/87sMxsAt+S8WooCQCQalGKycRV76rxbSxx76fJ
R0L6egouD14mi+cvU0ScFl4NMca5vSG5ke99KpwH62w6OzwO8ZsBnVrOsRYrjTH0
xRp/01t3ShWlRjjPAr63BbTqfOWI965rNvKHqPUCgYEA0QMvOTf7PMDOSuRoyQL9
f758YEifbKfCxMWOX6Qr18ZZzXR4W9pMvUEte0yER3g3OSi43dpCLiHCduU19gQW
FWiX2COEiX/CetCJmeQWyUYtLZzlstQdyTGqiDtJWrf1V0APAVNKNyoZSh4o3At9
EaAbaJeQpP0ceErbI8Qmup0CgYBwEyHQeVH1GLJAKu3Cdllx7lVjtkqHWADugosJ
xaq+Yre9PhlKyWGBxFC6puL37FKFy66wP4f6nS30BBipkAef6BrwC9tNkQZTNAze
3+xI7CzF0Tk8Wxw6bxALpxaSH9waXmaI5cyVQFxQKNgQRzaKfXr/+9aFNXU9aR3U
EhD5OQKBgBmsOHN1UkmKIkvybdIb86oci/Rcj6u2ZgiV01mjtkeJjHOK4gD6ZhHp
ikxEdmAkFno7I5AP1fSd9qDSmNR3w7/RfpLlK5rVhRuEBzxXLIiA+NrZCvGfWlOn
GVOlCU5+3ZuRb/JHRjN+aaylhzAdCWeAH/iWOKdeWZ2kuud243+n
-----END RSA PRIVATE KEY-----"""


    unsigned_credential = {"test" : 5}
    signed_credential = sign_credential(unsigned_credential, test_rsa_key)
    print(signed_credential, type(signed_credential))
    print(verify_credential(signed_credential, test_did))