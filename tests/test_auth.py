import json
import os
import time
from unittest.mock import MagicMock

import click
import jwt
import pytest
from functools import partial
from pathlib import Path

from kxicli import main
from click.testing import CliRunner
from kxicli.resources import auth
from kxicli.resources.auth import AuthCache
from kxi.auth import Authorizer
import mocks
from utils import return_none
import utils
from kxicli import common
from urllib3.exceptions import MaxRetryError, NewConnectionError

TEST_CLI = CliRunner()
test_cli_config = os.path.dirname(__file__) + '/files/test-cli-config'

common.config.config_file = os.path.dirname(__file__) + '/files/test-cli-config'
common.config.load_config("default")

current_time = int(time.time())
expires_at = current_time + 3600 
TEST_SERVICE_ACCOUNT_TOKEN = {
    "access_token": "abc1234",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "abc1234",
    "created_at": 1652741000,
    "expires_at": expires_at,
    "refresh_expires_in": 180
}

TEST_USER_TOKEN = {
    "access_token": "ABC456",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "ABC456",
    "created_at": 1652741000,
    "expires_at": 1652841000,
    "refresh_expires_in": 180
}

def get_test_context():
    return click.Context(click.Command('cmd'), obj={'profile': 'default'})

test_key_file = str(Path(__file__).parent / 'files' / 'test-key')
with open(test_key_file, 'rb') as f:
    test_key = f.read()
current_time = int(time.time())
TEST_VALID_TOKEN   = jwt.encode({"exp": str(current_time + 300)}, test_key, algorithm="RS256")
TEST_EXPIRED_TOKEN = jwt.encode({"exp": str(current_time - 300)}, test_key, algorithm="RS256")

def mock_fetch_user_token(self, redirect_host, redirect_port):
    return TEST_USER_TOKEN

def mock_return_true(*args, **kwargs):
    return True

def mock_fetch_none_default(option):
    return None

def mock_for_client(hostname, client_id, client_secret, realm, timeout):
    print('Mocking for_client call')
    # Add any mocking behavior here
    pass


def mock_get_serviceaccount_id():
    return 'user'

def mock_get_serviceaccount_secret():
    return 'pass'
    
def mock_fetch_token():
    return TEST_USER_TOKEN

def mock_valid_token_request(mocker):
    mocker.patch('requests.post', partial(
        mocks.http_response,
        status_code=200,
        content=json.dumps({'access_token': TEST_SERVICE_ACCOUNT_TOKEN}).encode('utf-8')
    ))

def get_test_context():
    return click.Context(click.Command('cmd'), obj={'profile': 'default'})


def mock_check_cached_token_active(cache_file):
    return TEST_SERVICE_ACCOUNT_TOKEN, auth.TokenType.SERVICEACCOUNT, True

@pytest.fixture
def mock_auth_functions(mocker):
    mocker.patch.object(Authorizer, 'fetch_token', return_value=MagicMock(access_token=TEST_SERVICE_ACCOUNT_TOKEN))
    mocker.patch.object(Authorizer, 'token', return_value=TEST_SERVICE_ACCOUNT_TOKEN)
    mocker.patch.object(Authorizer, 'check_cached_token', return_value=TEST_SERVICE_ACCOUNT_TOKEN)
    
    mocker.patch('kxicli.resources.auth.get_serviceaccount_token', return_none)
    
    
def test_print_token_returns_access_token(mocker, mock_auth_functions):
    common.config.load_config("default")
    ctx = get_test_context()
    mocker.patch('kxicli.resources.auth.check_cached_token_active', mock_check_cached_token_active) 
    result = TEST_CLI.invoke(main.cli, ['auth', 'print-token'])
    result.output.__contains__(TEST_SERVICE_ACCOUNT_TOKEN['access_token'])

def test_print_token_returns_invalid(mocker, mock_auth_functions):
    common.config.load_config("default")
    ctx = get_test_context()
    result = TEST_CLI.invoke(main.cli, ['auth', 'print-token'])
    assert result.output.__contains__('No valid token found in the file:')
    
def test_get_access_token_returns_access_token(mocker, mock_auth_functions):
    common.config.load_config("default")
    ctx = get_test_context()
    mocker.patch('kxicli.resources.auth.check_cached_token_active', mock_check_cached_token_active) 
    result = TEST_CLI.invoke(main.cli, ['auth', 'get-access-token'])
    assert result == TEST_SERVICE_ACCOUNT_TOKEN['access_token']


def test_user_login_hostname_exit(mocker):    
    mocker.patch.object(Authorizer, 'fetch_token', return_value=MagicMock(access_token=TEST_USER_TOKEN))
    mocker.patch.object(Authorizer, 'token', return_value=TEST_USER_TOKEN)
    mocker.patch.object(Authorizer, 'get_authorization_code', mock_fetch_user_token)
    mock_valid_token_request(mocker)
    mocker.patch('kxicli.common.get_default_val', mock_fetch_none_default)
    mocker.patch('kxicli.options.default_val', mock_fetch_none_default)
    
    mocker.patch('kxicli.resources.auth.check_cached_token_active', mock_check_cached_token_active) 
    result = TEST_CLI.invoke(main.cli, ['auth', 'login'])
    assert result.exit_code == 1 
    assert result.output.__contains__('Using hostname from config file')

    
    
def test_get_access_token_returns_access_token(mocker, mock_auth_functions):
    common.config.load_config("default")
    ctx = get_test_context()
    mocker.patch('kxicli.resources.auth.check_cached_token_active', mock_check_cached_token_active) 
    result = TEST_CLI.invoke(main.cli, ['auth', 'get-access-token'])
    result == TEST_SERVICE_ACCOUNT_TOKEN['access_token']
    
def test_get_admin_token(mocker):
    mock_valid_token_request(mocker)
    mocker.patch('kxicli.resources.auth.check_cached_token_active', mock_check_cached_token_active) 
    result = TEST_CLI.invoke(main.cli, ['auth', 'get-admin-token', '--username', 'username', '--password', 'test'])
    result == TEST_SERVICE_ACCOUNT_TOKEN['access_token']
    
    
def test_get_token_raises_exception(mocker):
    common.config.load_config("default")
    ctx = get_test_context()
    try:
        # Set the click context as the active context
        with ctx:
            authorizer = Authorizer(host='test.kx.com', realm='test', cache=AuthCache)
            mocker.patch.object(authorizer, 'for_client', mock_for_client)
            mocker.patch.object(authorizer, 'fetch_token', side_effect=[
                partial(mocks.http_response, status_code=404, content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')),
                mock_fetch_token
            ])     
            with pytest.raises(Exception) as e:
                auth.get_token(hostname='test.kx.com', realm='test')
            assert isinstance(e.value.__context__, MaxRetryError)
    finally:
        assert True

def test_get_token_returns_access_token(mocker, mock_auth_functions):
    common.config.load_config("default")
    ctx = get_test_context()
    
    try:
        # Set the click context as the active context
        with ctx:
            mocker.patch('kxicli.resources.auth.check_cached_token_active', mock_check_cached_token_active) 
            authorizer = Authorizer(host='test.kx.com', realm='test', cache=AuthCache)            
            mocker.patch.object(authorizer, 'for_client', mock_for_client)

            r = auth.get_token(hostname='test.kx.com', realm='test')
            assert r == TEST_SERVICE_ACCOUNT_TOKEN['access_token']
    finally:
        assert True


def test_get_admin_token_raises_exception(mocker):
    mocker.patch('requests.post', partial(
        mocks.http_response,
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))
    with pytest.raises(Exception) as e:
        auth.get_admin_token(hostname='test.kx.com', username='username', password='password')
    assert isinstance(e.value, click.ClickException)
    assert e.value.message == 'Failed to request admin access token:  404 None (<Response [404]>)'


def test_get_admin_token_returns_access_token(mocker):
    mock_valid_token_request(mocker)
    r = auth.get_admin_token(hostname='test.kx.com', username='username', password='password')
    assert isinstance(r, dict)
    assert r == TEST_SERVICE_ACCOUNT_TOKEN

def test_user_login(mocker):    
    common.config.load_config("default")
    ctx = get_test_context()
    mocker.patch.object(Authorizer, 'fetch_token', return_value=MagicMock(access_token=TEST_USER_TOKEN))
    mocker.patch.object(Authorizer, 'token', return_value=TEST_USER_TOKEN)
    mocker.patch.object(Authorizer, 'get_authorization_code', mock_fetch_user_token)
    mock_valid_token_request(mocker)
    
    mocker.patch('kxicli.resources.auth.check_cached_token_active', mock_check_cached_token_active) 
    result = TEST_CLI.invoke(main.cli, ['auth', 'login'])
    assert result.exit_code == 0

def test_user_login_auth(mocker):    
    common.config.load_config("default")
    ctx = get_test_context()
    mocker.patch.object(Authorizer, 'fetch_token', return_value=MagicMock(access_token=TEST_USER_TOKEN))
    mocker.patch.object(Authorizer, 'token', return_value=TEST_USER_TOKEN)
    mocker.patch.object(Authorizer, 'get_authorization_code', mock_fetch_user_token)

    with ctx:
        r = auth.user_login('https://hostname.kx.com',
                        'test-realm',
                        'localhost',
                        5000
                        )
        assert r.access_token == TEST_USER_TOKEN  



def test_read_and_write_to_cache():
    with utils.temp_file('test_token_cache') as temp_cache_file, get_test_context():
        auth.write_to_cache(TEST_USER_TOKEN, auth.TokenType.USER, temp_cache_file)
        token , tokenType = auth.read_from_cache(temp_cache_file) 
        assert (json.loads(token),tokenType) == (TEST_USER_TOKEN, auth.TokenType.USER)

def test_retrieve_token_as_user(mocker):
    common.config.load_config("default")
    ctx = get_test_context()
    mocker.patch.object(Authorizer, 'fetch_token', return_value=MagicMock(access_token=TEST_USER_TOKEN))
    mocker.patch.object(Authorizer, 'token', return_value=TEST_USER_TOKEN)
    mocker.patch.object(Authorizer, 'get_authorization_code', mock_fetch_user_token)

    with ctx:
        with utils.temp_file('test_token_cache') as temp_cache_file:
            auth.write_to_cache(TEST_USER_TOKEN, auth.TokenType.USER, temp_cache_file)
            assert auth.retrieve_token(hostname='https://hostname.kx.com',
                          realm='test-realm',
                          redirect_host='localhost',
                          redirect_port=5000,
                          token_type=auth.TokenType.USER,
                          ).access_token == TEST_USER_TOKEN
            token , tokenType = auth.read_from_cache(temp_cache_file) 
            assert (json.loads(token),tokenType) == (TEST_USER_TOKEN, auth.TokenType.USER)


def test_retrieve_token_as_serviceaccount(mocker):
    common.config.load_config("default")
    ctx = get_test_context()
    mocker.patch.object(Authorizer, 'fetch_token', return_value=MagicMock(access_token=TEST_SERVICE_ACCOUNT_TOKEN))
    mocker.patch.object(Authorizer, 'token', return_value=TEST_SERVICE_ACCOUNT_TOKEN)
    try:
        # Set the click context as the active context
        with ctx:
            authorizer = Authorizer(host='test.kx.com', realm='test', cache=AuthCache)
            mocker.patch.object(authorizer, 'for_client', mock_for_client)
            ctx.obj['serviceaccount_id'] = 'test'
            ctx.obj['serviceaccount_secret'] = 'pass'
            r = auth.retrieve_token(hostname='test.kx.com', realm='test',                               
                                    redirect_host='localhost',
                                    redirect_port=5000,
                                    token_type=auth.TokenType.SERVICEACCOUNT)
            assert r.return_value == TEST_SERVICE_ACCOUNT_TOKEN
    finally:
        assert True


def test_check_cached_token_active():
    with get_test_context():
        assert auth.check_cached_token_active('non_existent_file') == (None, None, False)

    with utils.temp_file('test_token_cache') as temp_cache_file, get_test_context():
        auth.write_to_cache(TEST_SERVICE_ACCOUNT_TOKEN, auth.TokenType.USER, temp_cache_file)
        assert auth.check_cached_token_active(temp_cache_file) == (TEST_SERVICE_ACCOUNT_TOKEN, auth.TokenType.USER, True)

        current_time = int(time.time())
        expires_at = current_time - 7200  # minus 2 hours 
        TEST_SERVICE_ACCOUNT_TOKEN['expires_at'] = expires_at
        auth.write_to_cache(TEST_SERVICE_ACCOUNT_TOKEN, auth.TokenType.USER, temp_cache_file)
        assert auth.check_cached_token_active(temp_cache_file) == (TEST_SERVICE_ACCOUNT_TOKEN, auth.TokenType.USER, False)




def get_token_returns_existing_valid_token():
    with utils.temp_file('test_token_cache') as temp_cache_file:
        auth.write_to_cache(TEST_VALID_TOKEN, temp_cache_file)
        assert auth.auth_get_token(hostname='https://hostname.kx.com',
                                   cache_file=temp_cache_file
                                   ) == TEST_VALID_TOKEN, "Cached token was returned"


def get_token_returns_new_token_when_cached_is_expired(mocker):
    mock = mocker.patch('kxi.auth.Authorizer.fetch_user_token', mock_fetch_user_token)
    with utils.temp_file('test_token_cache') as temp_cache_file:
        auth.write_to_cache(TEST_EXPIRED_TOKEN, temp_cache_file)
        assert auth.auth_get_token(hostname='https://hostname.kx.com',
                                   cache_file=temp_cache_file
                                   ) == TEST_USER_TOKEN, "A new token was returned"
        assert auth.read_from_cache(temp_cache_file) == TEST_USER_TOKEN, "The new token was cached"
    assert mock.call_count == 1

def test_determine_user_type(mocker):
    assert auth.TokenType.USER == auth.determine_token_type(None, None)

def test_cache_file_location(mocker):
    mocker.patch('kxicli.resources.auth.AuthCache.cache_file', return_none)
    mocker.patch('kxicli.resources.auth.write_to_cache', mock_return_true)
    mocker.patch('kxicli.resources.auth.AuthCache.load_grant_type', return_none)

    auth.AuthCache._save_token(token = TEST_SERVICE_ACCOUNT_TOKEN)