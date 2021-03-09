"""
DID SIOP Talao implementation

Reference :
https://identity.foundation/did-siop/
https://openid.net/specs/openid-connect-core-1_0.html#SelfIssued



    W3C did-siop is based on an oidc siop token flow (similar to an implicit flow), this flow is not acceptable within the current eidas regulation.
    So we use a standard athorization code flow. Identification is based on a verifiable claim which can be stored in wallet or on chain (Eerc735).The initiql request
    is extended with client did and signature for identification against user.

    User wallet is either a dapp, a dapp with a mobile connexion (walletconnect), or an mobile app.
    
    Flow
    1 : to log with his identity user scans a QR code on the Client application,he is redirected to the authorization server.
    2 : the authorization server establishes a connexion with the user wallet. Authentication is done through a DID signature and
    identification with a credential provided by the wallet. Within ERC735 this credential is encrypted and on chain, it will be downloaded and decryed by the wallet
    3 : w


Request

    openid://?response_type=code
        &client_id=https%3A%2F%2Frp.example.com%2Fcb
        &scope=openid%20did_authn
        &request=jwt





Test

    Main script to test web server through Gunicorn
    Arguments of main.py are in gunicornconf.py (global variables) :
    $ gunicorn -c gunicornconf.py  --reload wsgi:app
    if script is launched without Gunicorn, setup environment variables first :
    $ export MYCHAIN=talaonet
    $ export MYENV=livebox
    $ export AUTHLIB_INSECURE_TRANSPORT=1 # to be removed for production

"""
import sys
import os
import time
from flask import Flask, redirect
from flask_session import Session
from datetime import timedelta
import logging

import models
import oauth2
from routes import did_siop, server_utilities
from erc725 import oidc_environment

logging.basicConfig(level=logging.INFO)


# Environment variables set in gunicornconf.py  and transfered to environment.py
mychain = os.getenv('MYCHAIN')
myenv = os.getenv('MYENV')
if not mychain or not myenv :
    logging.error('environment variables missing')
    logging.error('export MYCHAIN=talaonet, export MYENV=livebox, export AUTHLIB_INSECURE_TRANSPORT=1')
    exit()
if mychain not in ['mainet', 'ethereum', 'rinkeby', 'talaonet'] :
    logging.error('wrong chain')
    exit()
logging.info('start to init environment')
mode = oidc_environment.currentMode(mychain,myenv)
logging.info('end of init environment')

# OIDC DID server Release
VERSION = "0.0.1"

# Framework Flask and Session setup
app = Flask(__name__)
app.jinja_env.globals['Version'] = VERSION
app.jinja_env.globals['Created'] = time.ctime(os.path.getctime('main.py'))
app.jinja_env.globals['Chain'] = mychain.capitalize()
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=180) # cookie lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "test_OIDC_DID" + mode.password
sess = Session()
sess.init_app(app)

# note that we set the 403 status explicitly
@app.errorhandler(403)
def page_abort(e):
    logging.warning('appel abort 403')
    return redirect(mode.server + 'login/')

oauth_config = {
    'OAUTH2_REFRESH_TOKEN_GENERATOR': False,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///' + mode.db_path + '/db.sqlite',
    'OAUTH2_TOKEN_EXPIRES_IN' : {
        'authorization_code': 300,
        #'implicit': 3000,
        #'password': 3000,
        'client_credentials': 3000
        }
    }
app.config.update(oauth_config)
models.db.init_app(app)
oauth2.config_oauth(app)

# FLASK ROUTES

# Server Management
app.add_url_rule('/api/v1', view_func=server_utilities.home, methods = ['GET', 'POST'], defaults ={'mode' : mode})
app.add_url_rule('/api/v1/create_client', view_func=server_utilities.create_client, methods = ['GET', 'POST'])

# Identity Provider
app.add_url_rule('/api/v1/oauth_login', view_func=did_siop.oauth_login, methods = ['GET', 'POST'], defaults ={'mode' : mode})
app.add_url_rule('/api/v1/oauth_login_larger', view_func=did_siop.oauth_login_larger, methods = ['GET', 'POST'], defaults ={'mode' : mode})
app.add_url_rule('/api/v1/oauth_wc_login/', view_func=did_siop.oauth_wc_login, methods = ['GET', 'POST'], defaults ={'mode' : mode})

app.add_url_rule('/api/v1/oauth_logout', view_func=did_siop.oauth_logout, methods = ['GET', 'POST'])
#app.add_url_rule('/api/v1/oauth_two_factor', view_func=web_oauth.oauth_two_factor, methods = ['GET', 'POST'], defaults ={'mode' : mode})

# Authorization Server
app.add_url_rule('/api/v1/authorize', view_func=did_siop.authorize, methods = ['GET', 'POST'], defaults={'mode' : mode})
app.add_url_rule('/api/v1/oauth/token', view_func=did_siop.issue_token, methods = ['POST'])
app.add_url_rule('/api/v1/oauth_revoke', view_func=did_siop.revoke_token, methods = ['GET', 'POST'])

# authorization code flow with user consent screen
app.add_url_rule('/api/v1/user_info', view_func=did_siop.user_info, methods = ['GET', 'POST'], defaults={'mode' : mode})

# miscallenous
app.add_url_rule('/api/v1/help', view_func=server_utilities.send_help)

# MAIN entry point : Flask API server

if __name__ == '__main__':

    # info release
    logging.info("created: %s", time.ctime(os.path.getctime(__file__)))
    logging.info('flask serveur on production now')

    app.run(host = mode.flaskserver, port= mode.port, debug = mode.test)
