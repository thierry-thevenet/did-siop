from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import csv
import sys
import time
import hashlib
import json
from datetime import datetime
from eth_account.messages import encode_defunct
import random
from eth_account import Account
import os

import logging
logging.basicConfig(level=logging.INFO)


# dependances
import talao_ipfs, ns
import constante

def read_profil (workspace_contract, mode, loading) :
	""" Read profil data as ERC725 claims witgout any decryption..."""

	# setup constante person
	person_topicnames = {'firstname' : 102105114115116110097109101,
						'lastname' : 108097115116110097109101,
						'contact_email' : 99111110116097099116095101109097105108,
						'contact_phone' : 99111110116097099116095112104111110101,
						'postal_address' : 112111115116097108095097100100114101115115,
						'birthdate' : 98105114116104100097116101,
						'about' : 97098111117116,
						'gender' : 103101110100101114,
						'education' : 101100117099097116105111110,
						'profil_title' : 112114111102105108095116105116108101,
						}

	# setup constant company
	company_topicnames = {'name' : 110097109101,
						'contact_name' : 99111110116097099116095110097109101,
						'contact_email' : 99111110116097099116095101109097105108,
						'contact_phone' : 99111110116097099116095112104111110101,
						'website' : 119101098115105116101,
						'about' : 97098111117116,
						'staff' : 115116097102102,
						'sales' : 115097108101115,
						'mother_company' : 109111116104101114095099111109112097110121,
						'siret' : 115105114101116,
						'siren' : 115105114101110,
						'postal_address' : 112111115116097108095097100100114101115115, }

	if loading != 'full' :
		person_topicnames = {'firstname' : 102105114115116110097109101,
							'lastname' : 108097115116110097109101,
							'profil_title' : 112114111102105108095116105116108101,
							}

		# setup constant company
		company_topicnames = {'name' : 110097109101,
							'siren' : 115105114101110,
							'postal_address' : 112111115116097108095097100100114101115115,}

	profil = dict()
	# test if identity exist and get category
	contract = mode.w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	try :
		category = contract.functions.identityInformation().call()[1]
	except :
		logging.error('get IdentityInformation failed')
		return None, None
	topic_dict = person_topicnames if category == 1001 else company_topicnames

	for topicname, topic in topic_dict.items() :
		claim = contract.functions.getClaimIdsByTopic(topic).call()
		if len(claim) == 0 :
			profil[topicname] = None
		else :
			claimId = claim[-1].hex()
			data = contract.functions.getClaim(claimId).call()
			profil[topicname]=data[4].decode('utf-8')
	return profil,category

def get_key_list(key, workspace_contract, mode) :
	contract = mode.w3.eth.contract(workspace_contract,abi = constante.workspace_ABI)
	return [ key.hex() for key in  contract.functions.getKeysByPurpose(key).call()]


def get_category (workspace_contract, mode) :
	contract = mode.w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	try :
		category = contract.functions.identityInformation().call()[1]
	except :
		logging.error('identity does not exist')
		return None
	return category


def get_private_key(address, mode) :
	if not mode.w3.isAddress(address) or address == '0x0000000000000000000000000000000000000000' :
		logging.error('wrong address')
		return None
	try :
		fp = open(mode.keystore_path + address[2:] + '.json', "r")
	except :
		logging.error('private key not found in privatekey.py')
		return None
	encrypted = fp.read()
	fp.close()
	return Account.decrypt(encrypted, mode.password).hex()


def get_rsa_key(address, mode) :
	if not mode.w3.isAddress(address) or address == '0x0000000000000000000000000000000000000000' :
		logging.error('wrong address')
		return None
	# first we try to find a the new rsa file with .pem
	workspace_contract = ownersToContracts(address, mode)
	previous_filename = mode.rsa_key_path + mode.BLOCKCHAIN + '/' + address + "_TalaoAsymetricEncryptionPrivateKeyAlgorithm1.txt"
	new_filename = mode.rsa_key_path + mode.BLOCKCHAIN + '/did:talao:' + mode.BLOCKCHAIN + ':'  + workspace_contract[2:] + ".pem"
	try :
		fp_new = open(new_filename,"r")
	except IOError :
		logging.warning('new RSA file (.pem) not found on disk')
		try :
			fp_prev = open(previous_filename,"r")
		except IOError :
			logging.warning('old RSA file not found on disk ')
			rsa_key  = None
		else :
			rsa_key = fp_prev.read()
			fp_prev.close()
			os.rename(previous_filename, new_filename)
			logging.warning('RSA file renamed')
	else :
		rsa_key = fp_new.read()
		fp_new.close()
		logging.info('new RSA file found')
	return rsa_key

def contractsToOwners(workspace_contract, mode) :
	if not workspace_contract :
		logging.error('wrong workspace_contract address')
		return None
	if workspace_contract == '0x0000000000000000000000000000000000000000' :
		logging.warning('contracts to owners return 0x...')
		return workspace_contract
	contract = mode.w3.eth.contract(mode.foundation_contract,abi=constante.foundation_ABI)
	address = contract.functions.contractsToOwners(workspace_contract).call()
	if address == '0x0000000000000000000000000000000000000000' :
		logging.error('wrong address')
		return None
	return address

def ownersToContracts(address, mode) :
	if not address :
		logging.warning('owners to contracts : its not an address')
		return None
	if address == '0x0000000000000000000000000000000000000000' :
		logging.warning('owners to contract : return 0x...')
		return address
	contract = mode.w3.eth.contract(mode.foundation_contract,abi=constante.foundation_ABI)
	workspace_address = contract.functions.ownersToContracts(address).call()
	if workspace_address == '0x0000000000000000000000000000000000000000' :
		logging.warning('owners to contract : return 0x...')
	return workspace_address


def has_vault_access(address, mode) :
	w3 = mode.w3
	contract=w3.eth.contract(mode.Talao_token_contract,abi=constante.Talao_Token_ABI)
	return contract.functions.hasVaultAccess(address, address).call()

def createVaultAccess(address,private_key,mode) :
	w3 = mode.w3
	contract=w3.eth.contract(mode.Talao_token_contract,abi=constante.Talao_Token_ABI)
	# calcul du nonce de l envoyeur de token
	nonce = w3.eth.getTransactionCount(address)
	# Build transaction
	txn = contract.functions.createVaultAccess(0).buildTransaction({'chainId': mode.CHAIN_ID,'gas': 150000,'gasPrice': w3.toWei(mode.GASPRICE, 'gwei'),'nonce': nonce,})
	#sign transaction with caller wallet
	signed_txn=w3.eth.account.signTransaction(txn,private_key)
	# send transaction
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)
	hash=w3.toHex(w3.keccak(signed_txn.rawTransaction))
	receipt = w3.eth.waitForTransactionReceipt(hash, timeout=2000, poll_latency=1)
	if not receipt['status'] :
		return None
		logging.error('transaction createvaut access failed')
	return hash

def createWorkspace(address,private_key,bRSAPublicKey,bAESEncryptedKey,bsecret,bemail,mode, user_type=1001) :
	w3 = mode.w3
	contract=w3.eth.contract(mode.workspacefactory_contract,abi=constante.Workspace_Factory_ABI)
	# calcul du nonce de l envoyeur de token . Ici le caller
	nonce = w3.eth.getTransactionCount(address)
	# Build transaction
	txn=contract.functions.createWorkspace(user_type,1,1,bRSAPublicKey,bAESEncryptedKey,bsecret,bemail).buildTransaction({'chainId': mode.CHAIN_ID,'gas': 6500000,'gasPrice': w3.toWei(mode.GASPRICE, 'gwei'),'nonce': nonce,})
	#sign transaction with caller wallet
	signed_txn=w3.eth.account.signTransaction(txn,private_key)
	# send transaction
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)
	hash= w3.toHex(w3.keccak(signed_txn.rawTransaction))
	receipt = w3.eth.waitForTransactionReceipt(hash, timeout=2000, poll_latency=1)
	if not receipt['status'] :
		logging.error('transaction createworkspace failed')
		return None
	return hash

def topicname2topicvalue(topicname) :
	topicvaluestr =''
	for i in range(0, len(topicname))  :
		a = str(ord(topicname[i]))
		if int(a) < 100 :
			a='0'+a
		topicvaluestr = topicvaluestr + a
	return int(topicvaluestr)


def update_self_claims(address, private_key, dict, mode) :
	# dict
	w3 = mode.w3
	chaine = ''
	offset = list()
	topic = list()
	for key in dict :
		#chaine = chaine + '_' + dict[key]
		#offset.append(len('_' +  dict[key]))
		chaine = chaine + dict[key]
		offset.append(len(dict[key]))
		topic.append(topicname2topicvalue(key))
	bchaine=bytes(chaine, 'utf-8')
	workspace_contract=ownersToContracts(address,mode)
	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	# calcul du nonce de l envoyeur de token . Ici le caller
	nonce = w3.eth.getTransactionCount(address)
	txn=contract.functions.updateSelfClaims(topic, bchaine,offset).buildTransaction({'chainId': mode.CHAIN_ID,'gas': 4000000,'gasPrice': w3.toWei(mode.GASPRICE, 'gwei'),'nonce': nonce,})
	signed_txn=w3.eth.account.signTransaction(txn,private_key)
	# send transaction
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)
	hash1= w3.toHex(w3.keccak(signed_txn.rawTransaction))
	receipt = w3.eth.waitForTransactionReceipt(hash1, timeout=2000, poll_latency=1)
	if receipt['status'] == 0 :
		logging.error('transaction update self claims failed')
		return None
	return hash1


#	0 identityInformation.creator = msg.sender;
#       1 identityInformation.category = _category;
#       2 identityInformation.asymetricEncryptionAlgorithm = _asymetricEncryptionAlgorithm;
#       3 identityInformation.symetricEncryptionAlgorithm = _symetricEncryptionAlgorithm;
#       4 identityInformation.asymetricEncryptionPublicKey = _asymetricEncryptionPublicKey;
#       5 identityInformation.symetricEncryptionEncryptedKey = _symetricEncryptionEncryptedKey;
#       6 identityInformation.encryptedSecret = _encryptedSecret;
def read_workspace_info (address, rsa_key, mode) :
	#return aes and secret as bytes
	w3 = mode.w3

	workspace_contract=ownersToContracts(address,mode)
	key = RSA.importKey(rsa_key)
	cipher = PKCS1_OAEP.new(key)

	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	data = contract.functions.identityInformation().call()
	category = data[1]

	#recuperer et decoder le secret crypté
	secret_encrypted=data[6]
	secret = cipher.decrypt(secret_encrypted)

	#recuperer et decoder la clé AES cryptée
	aes_encrypted=data[5]
	aes = cipher.decrypt(aes_encrypted)

	return category, secret, aes


