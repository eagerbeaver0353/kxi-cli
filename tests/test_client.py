import click
import pytest
import os

from click.testing import CliRunner

from kxicli import main
from kxicli import common
from kxicli.commands import client
from utils import return_none
import requests
import json
import mocks
from functools import partial

TEST_CLI = CliRunner()

test_cli_config = os.path.dirname(__file__) + '/files/test-cli-config'
common.config.config_file = test_cli_config
common.config.load_config("default")

def test_client_enrol(mocker):
    mocker.patch('kxicli.common.get_access_token', return_none)
    mocker.patch('requests.post', partial(
        mocks.http_response, 
        status_code=200,
        content=json.dumps({'message': "abc", 'detail': {'message': "another"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'enrol', '--hostname', 'test-host', '--name', 'test-client', '--insert-topic', 'test-topic', '--client-id', '1234', '--client-secret', 'super-secret', '--realm', 'test-realm'])
    assert result.exit_code == 0
    assert result.output == 'Using hostname from command line option: test-host\n{\n  "message": "abc",\n  "detail": {\n    "message": "another"\n  }\n}\n'

def test_client_remove(mocker):
    mocker.patch('kxicli.common.get_access_token', return_none)
    mocker.patch('requests.post', partial(
        mocks.http_response, 
        status_code=200,
        content=json.dumps({'message': "abc", 'detail': {'message': "another"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'remove', '--hostname', 'test-host', '--name', 'test-client', '--client-id', '1234', '--client-secret', 'super-secret', '--realm', 'test-realm'])
    assert result.exit_code == 0
    assert result.output == 'Using hostname from command line option: test-host\n{\n  "message": "abc",\n  "detail": {\n    "message": "another"\n  }\n}\n'

def test_client_info(mocker):
    mocker.patch('kxicli.common.get_access_token', return_none)
    mocker.patch('requests.get', partial(
        mocks.http_response, 
        status_code=200,
        content=json.dumps({'message': "abc", 'detail': {'message': "another"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'info', '--hostname', 'test-host', '--uid', 'abc1234'])
    assert result.exit_code == 0
    assert result.output == 'Using hostname from command line option: test-host\n{\n  "message": "abc",\n  "detail": {\n    "message": "another"\n  }\n}\n'

def test_client_list(mocker):
    mocker.patch('kxicli.common.get_admin_token', return_none)
    mocker.patch('requests.get', partial(
        mocks.http_response, 
        status_code=200,
        content=json.dumps({'message': "abc", 'detail': {'message': "another"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'list', '--hostname', 'test-host', '--realm', 'test-realm', '--username', 'user1', '--password', 'pass'])
    assert result.exit_code == 0
    assert result.output == 'Using hostname from command line option: test-host\n{\n  "message": "abc",\n  "detail": {\n    "message": "another"\n  }\n}\n'

def test_client_enrol_exception(mocker):
    mocker.patch('kxicli.common.get_access_token', return_none)
    mocker.patch('requests.post', partial(
        mocks.http_response, 
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))

    result = TEST_CLI.invoke(main.cli, ['client', 'enrol', '--hostname', 'test-host', '--name', 'test-client', '--insert-topic', 'test-topic', '--client-id', '1234', '--client-secret', 'super-secret', '--realm', 'test-realm'])
    assert result.exit_code == 1
    assert result.output == 'Using hostname from command line option: test-host\nError: Failed to enrol client:  404 None (<Response [404]>)\n'

def test_client_remove_exception(mocker):
    mocker.patch('kxicli.common.get_access_token', return_none)
    mocker.patch('requests.post', partial(
        mocks.http_response, 
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'remove', '--hostname', 'test-host', '--name', 'test-client', '--client-id', '1234', '--client-secret', 'super-secret', '--realm', 'test-realm'])
    assert result.exit_code == 1
    assert result.output == 'Using hostname from command line option: test-host\nError: Failed to remove client:  404 None (<Response [404]>)\n'

def test_client_info_exception(mocker):
    mocker.patch('kxicli.common.get_access_token', return_none)
    mocker.patch('requests.get', partial(
        mocks.http_response, 
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'info', '--hostname', 'test-host', '--uid', 'abc1234'])
    assert result.exit_code == 1
    assert result.output == 'Using hostname from command line option: test-host\nError: Failed to get client info:  404 None (<Response [404]>)\n'

def test_client_list_exception(mocker):
    mocker.patch('kxicli.common.get_admin_token', return_none)
    mocker.patch('requests.get', partial(
        mocks.http_response, 
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))
    result = TEST_CLI.invoke(main.cli, ['client', 'list', '--hostname', 'test-host', '--realm', 'test-realm', '--username', 'user1', '--password', 'pass'])
    assert result.exit_code == 1
    assert result.output == 'Using hostname from command line option: test-host\nError: Failed to list clients:  404 None (<Response [404]>)\n'
