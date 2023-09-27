from __future__ import annotations

import configparser
import json
import click
import jwt
from typing import Tuple
import requests
import time
from requests.exceptions import HTTPError
from enum import auto
from furl import furl
from typing import Optional
from pathlib import Path



from kxicli import options
from kxi.util import AutoNameEnum
from kxi.auth import Authorizer, GrantType
from kxi.auth import CredentialStore

from kxicli import log
from kxicli.common import sanitize_hostname, handle_http_exception, get_default_val, \
    key_hostname, key_keycloak_realm
from kxicli.options import get_serviceaccount_secret, get_serviceaccount_id

token_cache_path = Path.home() / '.insights'
token_cache_dir = str(token_cache_path)
token_cache_file = str(token_cache_path / 'credentials')
token_cache_format = "toml"

class TokenType(AutoNameEnum):
    """kdb Insights token type.

    Attributes:
        NONE: "Token type has not be set"
        SERVICEACCOUNT: "Token for a service account obtained from a client credentials flow"
        USER: "Token for a user account obtained from an authorization code flow"
    """
    SERVICEACCOUNT = auto()
    USER = auto()

cache_file = options.Option(
    config_name = 'cache.file',
    default= token_cache_file,
    help='Location to cache the auth token'
)

def get_serviceaccount_token(hostname, realm, token_type):
    """Get Keycloak client access token"""
    log.debug('Requesting access token')
    hostname = sanitize_hostname(hostname)
    
    store = CredentialStore(name = options.get_profile() ,file_path= token_cache_file, 
                            file_format= token_cache_format)

    auth = Authorizer(host=hostname, realm=realm,grant_type=token_type,
                    client_id=options.get_serviceaccount_id(),
                    client_secret = options.get_serviceaccount_secret(), 
                    cache=store
                    )

    auth.for_client(hostname, client_id=auth.client_id,
                    client_secret=auth.client_secret,realm=realm,timeout=None,
                    cache=store)
    return auth.token


def get_admin_token(hostname, username, password):
    """Get Keycloak Admin API token from hostname"""
    log.debug('Requesting admin access token')
    hostname = sanitize_hostname(hostname)
    url = f'https://{hostname}/auth/realms/master/protocol/openid-connect/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    payload = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': 'admin-cli'
    }

    try:
        r = requests.post(url, headers=headers, data=payload)
        r.raise_for_status()
        return r.json()['access_token']
    except HTTPError as e:
        handle_http_exception(e, 'Failed to request admin access token: ')


def user_login(hostname, realm, redirect_host, redirect_port) -> str:
    log.debug('Requesting user access token')
    store = CredentialStore(name = options.get_profile() ,file_path= token_cache_file, 
                            file_format= token_cache_format)

    auth = Authorizer(host=hostname, realm=realm,grant_type=TokenType.USER,
                    client_id=options.auth_client.retrieve_value(),cache=store
                    )
    token = auth.fetch_user_token(redirect_host=redirect_host,
                                  redirect_port=redirect_port
                                  )
    return token


def load_file(file: str) -> Tuple[str, configparser.ConfigParser]:
    """Load credentials file into a config parser and read profile name from context"""
    ctx = click.get_current_context()
    profile = ctx.find_root().obj.get('kxi_cli_profile', 'default')

    config = configparser.ConfigParser()
    config.optionxform = str
    config.read(file)

    if profile not in config:
        config[profile] = {}

    return profile, config


def write_to_cache(
    oauth_token_data: any,
    token_type: TokenType,
    cache_file: str = token_cache_file
):
    store = CredentialStore(name = options.get_profile() ,file_path= cache_file, 
                    file_format= token_cache_format)
    store.set(grant_type=token_type)
    store.set_token(oauth_token_data)


def cleanup_cache():
    """Remove cached token"""
    cache_file = options.cache_file.retrieve_value()
    profile, config = load_file(cache_file)

    # Check if the specified profile exists in the credentials file
    if profile in config:
        config.remove_section(profile)
        with open(cache_file, 'w') as f:
            config.write(f)


def retrieve_token(hostname: str,
    realm: str,
    redirect_host: str,
    redirect_port: int,
    token_type: TokenType,
) -> str:
    cleanup_cache()
    if token_type == TokenType.SERVICEACCOUNT:
        token = get_serviceaccount_token(hostname, realm, token_type)
    else:
        token = user_login(hostname, realm, redirect_host, redirect_port)
    
    click.echo('\nSuccessfully authenticated with kdb Insights Enterprise\n')
    return token


def check_cached_token_active(cache_file: str = token_cache_file) -> Tuple[str, TokenType, bool]:
    store = CredentialStore(name = options.get_profile() ,file_path= cache_file, 
                        file_format= token_cache_format)
    token_dict = store.get_token()

    if token_dict is None:
        return None, None, False

    if 'refresh_token' in token_dict:
        refresh_token_expires_at = token_dict['expires_at'] + \
            (token_dict['refresh_expires_in'] - token_dict['expires_in'])
        token_type = TokenType.USER
    else:
        refresh_token_expires_at = token_dict['expires_at']
        token_type = TokenType.SERVICEACCOUNT

    return token_dict, token_type,  int(refresh_token_expires_at) > time.time()

def get_token(hostname: str = get_default_val(key_hostname),
    realm: str = get_default_val(key_keycloak_realm),
    redirect_host: str = 'localhost',
    redirect_port: int = 4200,
) -> str:
    """
    Get a token from the cache if it's active and request one if not
    """
    serviceaccount_id = get_serviceaccount_id()
    serviceaccount_secret = get_serviceaccount_secret()
    cache_file = options.cache_file.retrieve_value()

    # if we have a token cached already, use that and prompt to auth again if it's expired
    token, token_type, active = check_cached_token_active(cache_file)
    if active:
        return token['access_token']


    # if theres no cached token, figure out the appropriate type
    if token_type is None:
        token_type = determine_token_type(serviceaccount_id, serviceaccount_secret)

    log.debug(f'Valid token not found, retrieving new {token_type.value} token.')
    return retrieve_token(hostname,
                     realm,
                     redirect_host,
                     redirect_port,
                     token_type
                     )


def determine_token_type(
    serviceaccount_id: str | None,
    serviceaccount_secret: str | None,
):
    """Figure out whether to use a serviceaccount flow or user flow"""

    # if there's no token cached, fall back to the current service account approach
    # and use --client-id & --client-secret passed on the command line or configured in the config file to get a token
    if serviceaccount_id is not None and serviceaccount_secret is not None:
        return TokenType.SERVICEACCOUNT

    # if there's no existing token and no service account credentials, prompt to auth (kxi auth login)
    return TokenType.USER
