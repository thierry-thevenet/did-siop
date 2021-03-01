"""
Main script to start web server through Gunicorn
Arguments of main.py are in gunicornconf.py (global variables) :
$ gunicorn -c gunicornconf.py  --reload wsgi:app

if script is launched without Gunicorn, setup environment variables first :
$ export MYCHAIN=talaonet
$ export MYENV=livebox
$ export AUTHLIB_INSECURE_TRANSPORT=1
$ python main.py

"""
import sys
import os
import time
from flask import Flask, redirect
from flask_session import Session
#from flask_fontawesome import FontAwesome
from datetime import timedelta

import models
import oauth2

from routes import web_oauth_did, web_resolver
from erc725 import oidc_environment

# Environment variables set in gunicornconf.py  and transfered to environment.py
mychain = os.getenv('MYCHAIN')
myenv = os.getenv('MYENV')
if not mychain or not myenv :
    print('Error : environment variables missing')
    print('Error : export MYCHAIN=talaonet, export MYENV=livebox, export AUTHLIB_INSECURE_TRANSPORT=1')
    exit()
if mychain not in ['mainet', 'ethereum', 'rinkeby', 'talaonet'] :
    print('Error : wrong chain')
    exit()
print('Success : start to init environment')
mode = oidc_environment.currentMode(mychain,myenv)
print('Success : end of init')

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
#app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["jpeg", "jpg", "png", "gif"]
sess = Session()
sess.init_app(app)

# bootstrap font managment  -> recheck if needed !!!!!
#fa = FontAwesome(app)

# note that we set the 403 status explicitly
@app.errorhandler(403)
def page_abort(e):
    print('Warning : appel abort 403')
    return redirect(mode.server + 'login/')

# Centralized @route for create identity
#app.add_url_rule('/register/',  view_func=web_create_identity.register, methods = ['GET', 'POST'], defaults={'mode': mode})
#app.add_url_rule('/register/password/',  view_func=web_create_identity.register_password, methods = [ 'GET', 'POST'], defaults={'mode': mode})
#app.add_url_rule('/register/code/', view_func=web_create_identity.register_code, methods = ['GET', 'POST'], defaults={'mode': mode})
#app.add_url_rule('/register/post_code/', view_func=web_create_identity.register_post_code, methods = ['POST', 'GET'], defaults={'mode': mode})
#app.add_url_rule('/wc_register/',  view_func=web_create_identity.wc_register, methods = ['GET', 'POST'], defaults={'mode': mode})
#app.add_url_rule('/wc_register_activate/',  view_func=web_create_identity.wc_register_activate, methods = ['GET', 'POST'], defaults={'mode': mode})

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

# Resolver
app.add_url_rule('/resolver', view_func=web_resolver.resolver, methods = ['GET', 'POST'], defaults ={'mode' : mode})

# Create credentials
app.add_url_rule('/api/v1', view_func=web_oauth_did.home, methods = ['GET', 'POST'], defaults ={'mode' : mode})
app.add_url_rule('/api/v1/create_client', view_func=web_oauth_did.create_client, methods = ['GET', 'POST'])

# Identity Provider
app.add_url_rule('/api/v1/oauth_login', view_func=web_oauth_did.oauth_login, methods = ['GET', 'POST'], defaults ={'mode' : mode})
app.add_url_rule('/api/v1/oauth_login_larger', view_func=web_oauth_did.oauth_login_larger, methods = ['GET', 'POST'], defaults ={'mode' : mode})
app.add_url_rule('/api/v1/oauth_wc_login/', view_func=web_oauth_did.oauth_wc_login, methods = ['GET', 'POST'], defaults ={'mode' : mode})

app.add_url_rule('/api/v1/oauth_logout', view_func=web_oauth_did.oauth_logout, methods = ['GET', 'POST'])
#app.add_url_rule('/api/v1/oauth_two_factor', view_func=web_oauth.oauth_two_factor, methods = ['GET', 'POST'], defaults ={'mode' : mode})

# Authorization Server
app.add_url_rule('/api/v1/authorize', view_func=web_oauth_did.authorize, methods = ['GET', 'POST'], defaults={'mode' : mode})
app.add_url_rule('/api/v1/oauth/token', view_func=web_oauth_did.issue_token, methods = ['POST'])
app.add_url_rule('/api/v1/oauth_revoke', view_func=web_oauth_did.revoke_token, methods = ['GET', 'POST'])

# authorization code flow with user consent screen
app.add_url_rule('/api/v1/user_info', view_func=web_oauth_did.user_info, methods = ['GET', 'POST'], defaults={'mode' : mode})

# miscallenous
app.add_url_rule('/api/v1/help', view_func=web_oauth_did.send_help)

# MAIN entry point : Flask API server

if __name__ == '__main__':

    # info release
    print('Info : ',__file__, " created: %s" % time.ctime(os.path.getctime(__file__)))
    print('Warning : flask serveur init')

    app.run(host = mode.flaskserver, port= mode.port, debug = mode.test)
