"""
https://w3c.github.io/did-spec-registries/#rsaverificationkey2018


"""
import os
import time
from flask import request, session, url_for, Response, abort, flash
from flask import render_template, redirect, jsonify
import json
from urllib.parse import urlencode, parse_qs, urlparse, parse_qsl
from urllib import parse
import random
from datetime import datetime, timedelta
from eth_account.messages import defunct_hash_message
from eth_account.messages import encode_defunct
from eth_account import Account
from eth_keys import keys
from eth_utils import decode_hex
import logging

import constante
import talao_ipfs
from erc725 import protocol
import ns

# Resolver pour l acces a un did. Cela retourne un debut de DID Document....
#@route('/resolver')
def resolver(mode):
    if request.method == 'GET' :
        if not request.args.get('username') and not request.args.get('did') :
            session['response'] = 'html'
            return render_template('resolver.html', output="")
        else :
            input = request.args.get('username')
            if not input :
                input = request.args.get('did')
    if request.method == 'POST' :
        input = request.form['input']
    try :
        if input[:3] == 'did' :
            did = input
            workspace_contract = '0x' + did.split(':')[3]
            username = ns.get_username_from_resolver(workspace_contract, mode)
        else :
            username = input.lower()
            workspace_contract = ns.get_data_from_username(username, mode).get('workspace_contract')
            did = 'did:talao:'+ mode.BLOCKCHAIN + ':' + workspace_contract[2:]
    except :
        logging.error('wrong input')
        output =  "Username, workspace_contract or did not found"
        return render_template('resolver.html', output=output)

    address = protocol.contractsToOwners(workspace_contract, mode)
    address = mode.w3.toChecksumAddress(address)
    contract = mode.w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
    rsa_public_key = contract.functions.identityInformation().call()[4]

    MAN_key = list()
    for count, value in enumerate(protocol.get_key_list(1, workspace_contract, mode), start=1) :
        key = {
            "id": did +"#key-act-" + str(count),
            "type": ["Secp256k1SignatureVerificationKey2018", "ERC725ActionKey"],
            "publicKeyHex Keccak256": value,
	        }
        MAN_key.append(key)

    ACT_key = list()
    for count, value in enumerate(protocol.get_key_list(2, workspace_contract, mode), start=1) :
        key = {
            "id": did +"#key-act-" + str(count),
            "type": ["Secp256k1SignatureVerificationKey2018", "ERC725ActionKey"],
            "publicKeyHex Keccak256": value,
            }
        ACT_key.append(key)

    CLA_key = list()
    for count, value in enumerate(protocol.get_key_list(3, workspace_contract, mode), start=1) :
        key = {
		    "id": did +"#key-cla-" + str(count),
		    "type": ["Secp256k1SignatureVerificationKey2018", "ERC725ClaimKey"],
		    "publicKeyHex Keccak256": value,
	        }
        CLA_key.append(key)

    ENC_key = list()
    for count, value in enumerate(protocol.get_key_list(4, workspace_contract, mode), start=1):
        key = {
		    "id": did +"#key-enc-" + str(count),
		    "type": ["Secp256k1SignatureVerificationKey2018", "ERC725EncryptionKey"],
		    "publicKeyHex Keccak256": value,
	        }
        ENC_key.append(key)

    DOC_key = list()
    for count, value in enumerate(protocol.get_key_list(20002, workspace_contract, mode), start=1):
        key = {
		    "id": did +"#key-doc-" + str(count),
		    "type": ["Secp256k1SignatureVerificationKey2018", "ERC725DocumentKey"],
		    "publicKeyHex Keccak256": value,
	        }
        DOC_key.append(key)

    payload = {
        "@context": ["https://www.w3.org/ns/did/v1", 
            {
		    "ERC725ManagementKey": "https://github.com/ethereum/EIPs/issues/725#ERC725ManagementKey",
		    "ERC725ActionKey": "https://github.com/ethereum/EIPs/issues/725#ERC725ActionKey",
		    "ERC725ClaimKey": "https://github.com/ethereum/EIPs/issues/725#ERC725ClaimKey",
		    "ERC725EncryptionKey": "https://github.com/ethereum/EIPs/issues/725#ERC725EncryptionKey",
	        }],
        'id' : did,
        "publicKey": [
            {"usage": "signing",
            "id": did + "#primary",
            "type": "Secp256k1VerificationKey2018",
            "publicKeyHex": workspace_contract,
            "controller": did},

            {"usage": "signing",
            "id": did + "#secondary",
            "type": "RSASigningKey2018",
            "publicKeyPem": rsa_public_key.decode('utf-8'),
            "controller": did},

            {"usage" : "signing",
            "id": did + "#owner",
            "type": "Secp256k1SignatureAuthentication2018",
            "blockchainAccountId":address},
            ],

        "authentication": {
		    "type": "Secp256k1SignatureAuthentication2018",
		    "publicKey": did + "#primary"},

        "service" : [],
        }

    payload['username'] = username
    payload['publicKey'].extend(MAN_key)
    payload['publicKey'].extend(ACT_key)
    payload['publicKey'].extend(CLA_key)
    payload['publicKey'].extend(ENC_key)
    payload['publicKey'].extend(DOC_key)


    if session.get('response') == 'html' :
        return render_template('resolver.html', output=json.dumps(payload, indent=4))
    else :
        response = Response(json.dumps(payload), status=200, mimetype='application/json')
        return response
