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
#from authlib.oauth2 import OAuth2Error, OAuth2Request
import json
#from urllib.parse import urlencode, parse_qs, urlparse, parse_qsl
from datetime import datetime, timedelta
import logging

import constante
import oauth2, ns
from models import db, User, OAuth2Client
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
    Client are Talao partners
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

def home():
    """
    @route('/api/v1', methods=('GET', 'POST'))
    """
    if request.method == 'GET':
        return render_template('home.html')

    if request.form['password'] != "123456" :
        print('ici')
        flash('wrong password', 'danger')
        return redirect ('/api/v1')
    return redirect('/api/v1/create_client')

def create_client() :
    if request.method == 'GET' :
        return render_template('create_client.html')

    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id="",
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

