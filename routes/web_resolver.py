
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

import constante
import talao_ipfs
from erc725 import protocol

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
        print('Error : wrong input')
        output =  "Username, workspace_contract or did not found"
        return render_template('resolver.html', output=output)
    address = protocol.contractsToOwners(workspace_contract, mode)
    address = mode.w3.toChecksumAddress(address)
    contract = mode.w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
    rsa_public_key = contract.functions.identityInformation().call()[4]
    priv_key = protocol.get_private_key(address, mode)
    if priv_key :
        priv_key_bytes = decode_hex(priv_key)
        priv_key = keys.PrivateKey(priv_key_bytes)
        public_key = str(priv_key.public_key)
    else :
        public_key = ""
    authn_list = contract.functions.getClaimIdsByTopic(100105100095097117116104110).call()
    if authn_list :
        did_authn_id = authn_list[-1].hex()
        claim = contract.functions.getClaim(did_authn_id).call()
        ipfs_hash = claim[5]
        did_authn = talao_ipfs.ipfs_get(ipfs_hash)
    else :
        did_authn_id = None
        did_authn = None
    payload = {'blockchain' : mode.BLOCKCHAIN,
                'username' : username,
                'did' : did,
                'ERC725_did_authn_claim_id' : did_authn_id,
                'did_authn' : did_authn,
                'address' : address,
                'ECDSA_public_key' : public_key,
                'RSA public key' : rsa_public_key.decode('utf-8'),
                'ACTION_key_keccak': protocol.get_key_list(1, workspace_contract, mode),
                'KEY_key_keccak': protocol.get_key_list(2, workspace_contract, mode),
                'CLAIM_key_keccak' : protocol.get_key_list(3, workspace_contract, mode),
                'DOCUMENT_key_keccak' : protocol.get_key_list(20002, workspace_contract, mode)}
    if session.get('response') == 'html' :
        return render_template('resolver.html', output=json.dumps(payload, indent=4))
    else :
        response = Response(json.dumps(payload), status=200, mimetype='application/json')
        return response
