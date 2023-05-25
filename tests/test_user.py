import click
import pytest
import os

from click.testing import CliRunner

from kxicli import main
from kxicli import common
from kxicli.commands import client
from utils import return_none
from mocks import http_response
from functools import partialmethod
import requests
import json

TEST_CLI = CliRunner()

test_cli_config = os.path.dirname(__file__) + '/files/test-cli-config'
common.config.config_file = test_cli_config
common.config.load_config("default")

def mocked_user_manager(*args, **kwargs):
    class MockUserManager:
        
        _raise_HTTP_Exception = partialmethod(http_response,
                          status_code=404,
                          content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8'))
    
        def __init__(self, host: str, username: str, password: str, user_realm: str = "insights", timeout: int = 2):
            pass
        
        def create_user(self, *args, **kwargs):
            self._raise_HTTP_Exception()

        def list_users(self, *args, **kwargs):
            self._raise_HTTP_Exception()
        
        def get_roles(self, *args, **kwargs):
            self._raise_HTTP_Exception()
        
        def get_assigned_roles(self, *args, **kwargs):
            self._raise_HTTP_Exception()
        
        def reset_password(self, *args, **kwargs):
            self._raise_HTTP_Exception()
        
        def assign_roles(self, *args, **kwargs):
            self._raise_HTTP_Exception()
        
        def remove_roles(self, *args, **kwargs):
            self._raise_HTTP_Exception()
        
        def delete_user(self, *args, **kwargs):
            self._raise_HTTP_Exception()

    return MockUserManager(*args, **kwargs)

def test_user_create_exception(mocker):
    mocker.patch('kxicli.commands.user.get_user_manager', mocked_user_manager)
    result = TEST_CLI.invoke(main.cli, ['user', 'create', 'testUser', '--hostname', 'test-host', '--password', 'test', '--admin-password', 'test'])
    assert result.exit_code == 1
    assert result.output == 'Error: Creating user failed with 404 None (<Response [404]>)\n'

def test_user_list_exception(mocker):
    mocker.patch('kxicli.commands.user.get_user_manager', mocked_user_manager)
    result = TEST_CLI.invoke(main.cli, ['user', 'list', '--hostname', 'test-host', '--admin-password', 'test'])
    assert result.exit_code == 1
    assert result.output == 'Error: Listing users failed with 404 None (<Response [404]>)\n'

def test_user_get_assigned_roles_exception(mocker):
    mocker.patch('kxicli.commands.user.get_user_manager', mocked_user_manager)
    result = TEST_CLI.invoke(main.cli, ['user', 'get-assigned-roles', 'test-user', '--hostname', 'test-host', '--admin-password', 'test'])
    assert result.exit_code == 1
    assert result.output == 'Error: Getting roles for user failed with 404 None (<Response [404]>)\n'

def test_user_get_available_roles_exception(mocker):
    mocker.patch('kxicli.commands.user.get_user_manager', mocked_user_manager)
    result = TEST_CLI.invoke(main.cli, ['user', 'get-available-roles', '--hostname', 'test-host', '--admin-password', 'test'])
    assert result.exit_code == 1
    assert result.output == 'Error: Getting roles failed with 404 None (<Response [404]>)\n'

def test_user_reset_password_exception(mocker):
    mocker.patch('kxicli.commands.user.get_user_manager', mocked_user_manager)
    result = TEST_CLI.invoke(main.cli, ['user', 'reset-password', 'testUser', '--hostname', 'test-host', '--password', 'test', '--admin-password', 'test'])
    assert result.exit_code == 1
    assert result.output == 'Error: Resetting user password failed with 404 None (<Response [404]>)\n'

def test_user_assign_roles_exception(mocker):
    mocker.patch('kxicli.commands.user.get_user_manager', mocked_user_manager)
    result = TEST_CLI.invoke(main.cli, ['user', 'assign-roles', 'testUser', '--roles', 'r1,r2,r3', '--hostname', 'test-host', '--admin-password', 'test'])
    assert result.exit_code == 1
    assert result.output == 'Error: Assigning roles failed with 404 None (<Response [404]>)\n'

def test_user_remove_roles_exception(mocker):
    mocker.patch('kxicli.commands.user.get_user_manager', mocked_user_manager)
    result = TEST_CLI.invoke(main.cli, ['user', 'remove-roles', 'testUser', '--roles', 'r1,r2,r3', '--hostname', 'test-host', '--admin-password', 'test'])
    assert result.exit_code == 1
    assert result.output == 'Error: Removing roles failed with 404 None (<Response [404]>)\n'

def test_user_delete_exception(mocker):
    mocker.patch('kxicli.commands.user.get_user_manager', mocked_user_manager)
    result = TEST_CLI.invoke(main.cli, ['user', 'delete', 'testUser', '--hostname', 'test-host', '--admin-password', 'test', '--force'])
    assert result.exit_code == 1
    assert result.output == 'Error: Deleting user failed with 404 None (<Response [404]>)\n'