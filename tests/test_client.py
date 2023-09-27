import time
import click
import pytest
import os

from click.testing import CliRunner
from unittest.mock import MagicMock

from kxicli import main
from kxicli import common
from kxi.util import AutoNameEnum
from kxicli.commands import client
from kxi.auth import Authorizer
from utils import return_none
import utils
import requests
import json
import mocks
from functools import partial

TEST_CLI = CliRunner()

test_cli_config = os.path.dirname(__file__) + '/files/test-cli-config'
common.config.config_file = test_cli_config
common.config.load_config("default")

current_time = int(time.time())
expires_at = current_time + 3600 
TEST_SERVICE_ACCOUNT_TOKEN = {
    "access_token": "abc1234",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "abc1234",
    "created_at": 1652741000,
    "expires_at": expires_at
}

def get_test_context():
    return click.Context(click.Command('cmd'), obj={'profile': 'default'})

def mock_client_response(*args, **kwargs):
    return {'message': "abc", 'detail': {'message': "another"}}


@pytest.fixture
def mock_auth_functions(mocker):
    mocker.patch.object(Authorizer, 'fetch_token', return_value=MagicMock(access_token=TEST_SERVICE_ACCOUNT_TOKEN))
    mocker.patch.object(Authorizer, 'token', return_value=TEST_SERVICE_ACCOUNT_TOKEN)
    mocker.patch.object(Authorizer, '_check_cached_token', return_value=TEST_SERVICE_ACCOUNT_TOKEN)
    
    mocker.patch('kxicli.resources.auth.check_cached_token_active', return_none)
    mocker.patch('kxicli.resources.auth.get_serviceaccount_token', return_none)
    
def test_client_enrol(mocker, mock_auth_functions):
    mocker.patch('kxi.client_controller.ClientController.enrol', mock_client_response)

    result = TEST_CLI.invoke(main.cli, ['client', 'enrol', '--hostname', 'test-host', '--name', 'test-client', '--insert-topic', 'test-topic', '--client-id', '1234', '--client-secret', 'super-secret', '--realm', 'test-realm'])
    assert result.exit_code == 0
    assert result.output == '{\n  "message": "abc",\n  "detail": {\n    "message": "another"\n  }\n}\n'

def test_client_remove(mocker, mock_auth_functions):
    mocker.patch('kxi.client_controller.ClientController.leave', mock_client_response)

    result = TEST_CLI.invoke(main.cli, ['client', 'remove', '--hostname', 'test-host', '--name', 'test-client', '--client-id', '1234', '--client-secret', 'super-secret', '--realm', 'test-realm'])
    assert result.exit_code == 0
    assert result.output == '{\n  "message": "abc",\n  "detail": {\n    "message": "another"\n  }\n}\n'

def test_client_info(mocker):
    mocker.patch('kxicli.resources.auth.get_serviceaccount_token', return_none)
    mocker.patch('requests.get', partial(
        mocks.http_response, 
        status_code=200,
        content=json.dumps({'message': "abc", 'detail': {'message': "another"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'info', '--hostname', 'test-host', '--uid', 'abc1234'])
    assert result.exit_code == 0
    assert result.output == '{\n  "message": "abc",\n  "detail": {\n    "message": "another"\n  }\n}\n'

def test_client_list(mocker):
    mocker.patch('kxicli.resources.auth.get_admin_token', return_none)
    mocker.patch('requests.get', partial(
        mocks.http_response, 
        status_code=200,
        content=json.dumps({'message': "abc", 'detail': {'message': "another"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'list', '--hostname', 'test-host', '--realm', 'test-realm', '--username', 'user1', '--password', 'pass'])
    assert result.exit_code == 0
    assert result.output == 'DeprecationWarning: The command \'list\' is deprecated.\n{\n  "message": "abc",\n  "detail": {\n    "message": "another"\n  }\n}\n'

def test_client_enrol_exception(mocker, mock_auth_functions):
    mocker.patch('kxicli.resources.auth.get_serviceaccount_token', return_none)
    mocker.patch('kxi.client_controller.ClientController.enrol', partial(
        mocks.http_response, 
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))

    result = TEST_CLI.invoke(main.cli, ['client', 'enrol', '--hostname', 'test-host', '--name', 'test-client', '--insert-topic', 'test-topic', '--client-id', '1234', '--client-secret', 'super-secret', '--realm', 'test-realm'])
    
    assert isinstance(result.exception, requests.exceptions.HTTPError)
    assert result.exit_code == 1

def test_client_remove_exception(mocker, mock_auth_functions):
    mocker.patch('kxicli.resources.auth.get_serviceaccount_token', return_none)
    mocker.patch('kxi.client_controller.ClientController.leave', partial(
        mocks.http_response, 
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'remove', '--hostname', 'test-host', '--name', 'test-client', '--client-id', '1234', '--client-secret', 'super-secret', '--realm', 'test-realm'])
    assert isinstance(result.exception, requests.exceptions.HTTPError)
    assert result.exit_code == 1
    
def test_client_info_exception(mocker):
    mocker.patch('kxicli.resources.auth.get_serviceaccount_token', return_none)
    mocker.patch('requests.get', partial(
        mocks.http_response, 
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'info', '--hostname', 'test-host', '--uid', 'abc1234'])
    assert result.exit_code == 1
    assert result.output == 'Error: Failed to get client info:  404 None (<Response [404]>)\n'

def test_client_list_exception(mocker):
    mocker.patch('kxicli.resources.auth.get_admin_token', return_none)
    mocker.patch('requests.get', partial(
        mocks.http_response, 
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'list', '--hostname', 'test-host', '--realm', 'test-realm', '--username', 'user1', '--password', 'pass'])
    assert result.exit_code == 1
    assert result.output == 'DeprecationWarning: The command \'list\' is deprecated.\nError: Failed to list clients:  404 None (<Response [404]>)\n'
