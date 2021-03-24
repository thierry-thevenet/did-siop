from authlib.integrations.flask_oauth2 import (
    AuthorizationServer, ResourceProtector)
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func,
    create_bearer_token_validator,
    create_revocation_endpoint,
)

from authlib.oauth2.rfc6749 import grants # ajout
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from authlib.oidc.core.grants import (
    OpenIDCode as _OpenIDCode,
    OpenIDImplicitGrant as _OpenIDImplicitGrant,
    OpenIDHybridGrant as _OpenIDHybridGrant,
)
from authlib.oauth2.rfc6749.errors import (
    OAuth2Error,
    InvalidGrantError,
    InvalidScopeError,
    UnsupportedGrantTypeError,
)
from authlib.oidc.core import UserInfo
from werkzeug.security import gen_salt
from authlib.jose import jwk
from Crypto.PublicKey import RSA
import time
import datetime
import os
import json
import logging
logging.basicConfig(level=logging.INFO)

from erc725 import oidc_environment, protocol
from models import db, User
from models import OAuth2Client, OAuth2AuthorizationCode, OAuth2Token
import constante
import ns

# Environment setup
mychain = os.getenv('MYCHAIN')
myenv = os.getenv('MYENV')
mode = oidc_environment.currentMode(mychain,myenv)

private_rsa_key = protocol.get_rsa_key(mode.owner_talao, mode)

# Generate JWK from rsa key
JWK = jwk.dumps(private_rsa_key)

# set up 'kid' in the JWK header
JWK['kid'] = "did:talo:talaonet:c5C1B070b46138AC3079cD9Bce10010d6e1fCD8D#secondary"

JWT_CONFIG = {
    'key':  JWK,
    'alg': 'RS256',
    'iss': 'did:talao:' + mode.BLOCKCHAIN + ':' + mode.workspace_contract_talao[2:],
    'exp': 3600,
    }

def exists_nonce(nonce, req):
    exists = OAuth2AuthorizationCode.query.filter_by(
        client_id=req.client_id, nonce=nonce
    ).first()
    return bool(exists)

# for JWT generation only
def generate_user_info(user, scope):
    user_workspace_contract = user.username
    did = 'did:talao:' + mode.BLOCKCHAIN +':' + user_workspace_contract[2:]
    user_info = UserInfo(sub=did)
    user_info['credential'] = json.dumps(json.loads(ns.get_vc(did)[0])["did_authn"])
     # credential is deleted
    try :
        ns.del_vc(did)
    except :
        logging.error('credential deletion failed')
    return user_info


def create_authorization_code(client, grant_user, request):
    code = gen_salt(48)
    nonce = request.data.get('nonce')
    item = OAuth2AuthorizationCode(
        code=code,
        client_id=client.client_id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        user_id=grant_user.id,
        nonce=nonce,
    )
    db.session.add(item)
    db.session.commit()
    return code

class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    #def create_authorization_code(self, client, grant_user, request):
    #    return create_authorization_code(client, grant_user, request)

    def query_authorization_code(self, code, client): # parse
        item = OAuth2AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code) :
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)

    def save_authorization_code(self, code, request): # ajouté pour remplacer create
        client = request.client
        item = OAuth2AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
            )
        db.session.add(item)
        db.session.commit()
        return code

class OpenIDCode(_OpenIDCode):
    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_audiences(self, request):
        """Parse `aud` value for id_token, default value is client id. Developers
        MAY rewrite this method to provide a customized audience value.
        """
        return ['did:talao:' + mode.BLOCKCHAIN + ':' + mode.workspace_contract_talao[2:]]

    def get_jwt_config(self, grant):
        return JWT_CONFIG

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)


class OpenIDImplicitGrant(_OpenIDImplicitGrant):
    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_audiences(self, request):
        """Parse `aud` value for id_token, default value is client id. Developers
        MAY rewrite this method to provide a customized audience value.
        """
        return ['did:talao:' + mode.BLOCKCHAIN + ':' + mode.workspace_contract_talao[2:]]

    def get_jwt_config(self):
        return JWT_CONFIG

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)

"""
class HybridGrant(_OpenIDHybridGrant):
    def create_authorization_code(self, client, grant_user, request):
        return create_authorization_code(client, grant_user, request)

    def exists_nonce(self, nonce, request):
        return exists_nonce(nonce, request)

    def get_jwt_config(self):
       return JWT_CONFIG

    def generate_user_info(self, user, scope):
        return generate_user_info(user, scope)
"""

authorization = AuthorizationServer()
require_oauth = ResourceProtector()


def config_oauth(app):
    query_client = create_query_client_func(db.session, OAuth2Client)
    save_token = create_save_token_func(db.session, OAuth2Token)
    authorization.init_app(
        app,
        query_client=query_client,
        save_token=save_token
    )

    # support all openid grants
    authorization.register_grant(AuthorizationCodeGrant, [
        OpenIDCode(require_nonce=True),
    ])
    #authorization.register_grant(ImplicitGrant)
    #authorization.register_grant(OpenIDImplicitGrant)
    #authorization.register_grant(HybridGrant)
    #authorization.register_grant(grants.ClientCredentialsGrant)
    #authorization.register_grant(RefreshTokenGrant)
    #authorization.register_grant(PasswordGrant)

    # protect resource
    bearer_cls = create_bearer_token_validator(db.session, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())

    # support revocation
    revocation_cls = create_revocation_endpoint(db.session, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

