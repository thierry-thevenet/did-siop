"""
This module manages a simple did (Self Sovereign Identity) integration to a standard OIDC Server
wallet are standard mobile crypto wallets compliant with walletconnect protocol
They are only used to sign for authentication and to sned an encrypted ID token 
Sign method is eth_sign, no use of JWT as lib have not not been found for ECDSA Ethereum address in JS and Python
Encryption and eblockchain access are managed client side JS (Dapp) with walletconnect provider
We use talaonet POA private chain
"""
import os
import time
from flask import request, session, url_for, Response, abort, flash
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token, client_authenticated
from authlib.oauth2 import OAuth2Error, OAuth2Request
from models import db, User, OAuth2Client
import json
from urllib.parse import urlencode, parse_qs, urlparse, parse_qsl
from urllib import parse
from datetime import datetime, timedelta
import logging
#from eth_account.messages import defunct_hash_message
#from eth_account.messages import encode_defunct
from eth_account import Account
from eth_keys import keys
#from eth_utils import decode_hex

import constante
import oauth2
import ns
import talao_ipfs
from erc725 import protocol

logging.basicConfig(level=logging.INFO)

def check_login() :
    """
    check if the user is correctly logged. This function is called everytime a user function is called from Talao website
    """
    if not session.get('username') and not session.get('workspace_contract') :
        logging.error('call abort 403')
        abort(403)
    else :
        return session['username']


# To be rework
def get_resume (workspace_contract, mode) :
    return dict()
"""
def get_resume(workspace_contract, mode) :
    user = Identity(workspace_contract, mode, authenticated=False)
    # clean up Identity to get a resume
    resume = user.__dict__.copy()
    attr_list  = ['synchronous', 'authenticated', 'address', 'workspace_contract','did',
        'other_list', 'education_list', 'experience_list', 'kbis_list', 'certificate_list','skills_list',
        'file_list', 'issuer_keys', 'partners', 'category', 'personal', 'private_key', 'rsa_key', 'picture',
        'signature', 'kyc', 'relay_activated', 'identity_file', 'profil_title', 'type', 'name']
    for attr in attr_list :
        del resume[attr]
    return resume
"""

def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None

def split_by_crlf(s):
    return [v for v in s.splitlines() if v]

def get_client_workspace(client_id, mode) :
    """
    Client application are found by username
    We know them as they have credentials to access the server
    Client are patners
    """
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    client_username = json.loads(client._client_metadata)['client_name']
    return ns.get_data_from_username(client_username, mode).get('workspace_contract')

def get_user_workspace(user_id, mode):
    user = User.query.get(user_id)
    return user.username


def send_help():
    """
    @app.route('/api/v1/help/')
    help files upload
    """
    filename = request.args['file']
    return render_template(filename)


def home(mode):
    """
    @route('/api/v1', methods=('GET', 'POST'))
    This function is called from the Talao identity to create  client API credentials for authorization server
    """
    check_login()
    if request.method == 'POST':
        username = request.form.get('username')
        workspace_contract = ns.get_data_from_username(username, mode).get('workspace_contract')
        user = User.query.filter_by(username=workspace_contract).first()
        if not user:
            user = User(username=workspace_contract)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        # if user is not just to log in, but need to head back to the auth page, then go for it
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect('/api/v1')
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []
    return render_template('home.html', user=user, clients=clients)

#@route('/api/v1/oauth_logout')
def oauth_logout():
    post_logout = request.args.get('post_logout_redirect_uri')
    session.clear()
    logging.info('logout ID provider')
    return redirect(post_logout)


def oauth_login(mode):
    """
    @route('/api/v1/oauth_login')
    Identity Provider login FIRST CALL
    Inital call from authorization server redirect
    """
    if not session.get('url') :
        session['url'] = request.args.get('next')
        print('next = ', session['url'])
    return render_template('login_qrcode.html')


def oauth_login_larger(mode):
    """
    #@route('/api/v1/oauth_login_larger')
    larger QR code
    """
    return render_template('login_mobile.html')



def oauth_wc_login(mode) :
    """
    @app.route('/oauth_wc_login/', methods = ['GET', 'POST'])
    Identity provider login follow up, "IODC confirm screen"
    This functions helps to check if wallet address is an ethereum and if it is an Identity address 
    """
    if request.method == 'GET' :
        wallet_address = request.args.get('wallet_address')

        # if the QR code scan has been refused or wallet address cannot be read we reject
        if 'reject' in  request.args or wallet_address == 'undefined' :
            return redirect(session.get('url', '')+'&reject=on')

        # look for the wallet logo on server if logo is not provided by walletwonnect
        src = request.args.get('wallet_logo')
        if src in ['undefined', None] :
            filename= request.args.get('wallet_name').replace(' ', '').lower()
            src = "/static/img/wallet/" + filename + ".png"

        # cleanup address
        wallet_address = mode.w3.toChecksumAddress(wallet_address)

        # check if wallet address is an owner, one rejects alias wallet here
        logging.info("Wallet is an owner of  = %s", protocol.ownersToContracts(wallet_address, mode))
        logging.info('Info : Wallet is an alias of = %s', ns.get_username_from_wallet(wallet_address, mode))
        identity = protocol.ownersToContracts(wallet_address, mode)
        if not identity or identity == '0x0000000000000000000000000000000000000000' :
            return render_template('wc_reject.html', wallet_address=wallet_address)

        data = dict(parse.parse_qsl(parse.urlsplit(session['url']).query))
        return render_template('wc_confirm.html',
								wallet_address=wallet_address,
                                **data,
								#nonce_hex= '0x' + bytes(data['nonce'], 'utf-8').hex(),
								wallet_name = request.args.get('wallet_name'),
								wallet_logo= src)

    if request.method == 'POST' :
        wallet_address = request.form.get('wallet_address')
        if not wallet_address :
            return render_template('login_qrcode.html')
        # look  for username depending on wallet address
        workspace_contract = protocol.ownersToContracts(wallet_address, mode)
        if not workspace_contract :
            workspace_contract = ns.get_workspace_contract_from_wallet(wallet_address, mode)
        user = User.query.filter_by(username=workspace_contract).first()
        if not user:
            user = User(username=workspace_contract)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        url = session['url']
        return redirect(url + '&wallet_address=' + wallet_address)


def create_client():
    """
    @route('/api/v1/create_client', methods=('GET', 'POST'))
    This function is called from the Talao website to create client API credentials for authorization server
    as OIDC requiremets
    """
    check_login()
    user = current_user()
    if not user:
        return redirect('/api/v1')
    if request.method == 'GET':
        return render_template('create_client.html')
    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )
    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)
    if form['token_endpoint_auth_method'] == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)
    db.session.add(client)
    db.session.commit()
    return redirect('/api/v1')

#@route('/oauth/revoke', methods=['POST'])
def revoke_token():
    return oauth2.authorization.create_endpoint_response('revocation')

#@route('/api/v1/oauth/token', methods=['POST'])
def issue_token():
    response = oauth2.authorization.create_token_response()
    return response

def authorize(mode):
    """
    @route('/api/v1/authorize', methods=['GET', 'POST'])
    Authorization server as OIDC requirements
    """
    # to manage wrong login ot user rejection, qr code exit
    if 'reject' in request.args :
        logging.warning('reject in authorize')
        session.clear()
        return oauth2.authorization.create_authorization_response(grant_user=None)

    # get client Identity from API credentials
    user = current_user()
    client_id = request.args.get('client_id')
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    client_workspace_contract = get_client_workspace(client_id, mode)

    # if user not logged (Auth server), then to log it in
    if not user :
        return redirect(url_for('oauth_login', next=request.url))

    # if user is already logged we prepare the "OIDC consent screen"
    if request.method == 'GET' :
        try:
            grant = oauth2.authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            logging.error('OAuth2Error')
            return jsonify(dict(error.get_body()))
            #return error.error

        # configure consent screen : oauth_authorize.html
        consent_screen_scopes = ['openid', 'address', 'profile', 'about', 'birthdate', 'resume', 'proof_of_identity', 'email', 'phone']
        user_workspace_contract = user.username
        checkbox = {key.replace(':', '_') : 'checked' if key in grant.request.scope.split() and key in client.scope.split() else ""  for key in consent_screen_scopes}

        # Display consent view to ask for user consent if scope is more than just openid
        return render_template('authorize.html',
                                user=user,
                                grant=grant,
                                **checkbox,
                                wallet_signature=request.args.get('wallet_signature'),
                                workspace_contract_to= client_workspace_contract)

    # POST, call from consent screen
    signature = request.form.get('signature')
    message = request.form.get('message')
    if not user and 'username' in request.form:
        username = request.form.get('username')
        user_workspace_contract = ns.get_data_from_username(username, mode)['workspace_contact']
        user = User.query.filter_by(username=user_workspace_contract).first()
    if 'reject' in request.form :
        session.clear()
        logging.info('reject')
        return oauth2.authorization.create_authorization_response(grant_user=None,)
    # update scopes after user consent
    query_dict = parse_qs(request.query_string.decode("utf-8"))
    my_scope = ""
    for scope in query_dict['scope'][0].split() :
        if request.form.get(scope) :
            my_scope = my_scope + scope + " "
    query_dict["scope"] = [my_scope[:-1]]
    # we setup a custom Oauth2Request as we have changed the scope in the query_dict
    req = OAuth2Request("POST", request.base_url + "?" + urlencode(query_dict, doseq=True))
    return oauth2.authorization.create_authorization_response(message=message, signature=signature, grant_user=user, request=req,)


@oauth2.require_oauth('address openid profile resume email birthdate proof_of_identity about resume gender name contact_phone website', 'OR')
def user_info(mode):
    """
    # standard OIDC user info endpoint
    #route('/api/v1/user_info')
    """
    user_id = current_token.user_id
    user_workspace_contract = get_user_workspace(user_id,mode)
    user_info = dict()
    profile, category = protocol.read_profil(user_workspace_contract, mode, 'full')
    user_info['sub'] = 'did:talao:' + mode.BLOCKCHAIN +':' + user_workspace_contract[2:]
    logging.info('token scope received = %s', current_token.scope)
    if 'proof_of_identity' in current_token.scope :
        user_info['proof_of_identity'] = 'Not implemented yet'
    if category == 1001 : # person
        if 'profile' in current_token.scope :
            user_info['given_name'] = profile.get('firstname')
            user_info['family_name'] = profile.get('lastname')
            user_info['gender'] = profile.get('gender')
        for scope in ['email', 'phone', 'birthdate', 'about'] :
            if scope in current_token.scope :
                user_info[scope] = profile.get(scope) if profile.get(scope) != 'private' else None
        if 'address' in current_token.scope :
            user_info['address'] = profile.get('postal_address') if profile.get('postal_address') != 'private' else None
        if 'resume' in current_token.scope :
            print('user wokspace contract dans appel de resume = ', user_workspace_contract)
            user_info['resume'] = get_resume(user_workspace_contract, mode)
    if category == 2001 : # company
        logging.warning('OIDC request for company')
    # setup response
    response = Response(json.dumps(user_info), status=200, mimetype='application/json')
    return response


