import click
import pytest

from click.testing import CliRunner

from kxicli import main
from kxicli import common
from kxicli.commands import client
from utils import return_none

TEST_CLI = CliRunner()

def test_client_enrol_exception(mocker):
    mocker.patch('kxicli.common.get_access_token', return_none)
    mocker.patch('requests.post', return_none)
    result = TEST_CLI.invoke(main.cli, ['client', 'enrol', '--hostname', 'test-host', '--name', 'test-client', '--insert-topic', 'test-topic', '--client-id', '1234', '--client-secret', 'super-secret', '--realm', 'test-realm'])
    assert result.exit_code == 1
    assert result.output == 'Error: Failed to enrol client\n'


def test_client_remove_exception(mocker):
    mocker.patch('kxicli.common.get_access_token', return_none)
    mocker.patch('requests.post', return_none)
    result = TEST_CLI.invoke(main.cli, ['client', 'remove', '--name', 'test-client'])
    assert result.exit_code == 1
    assert result.output == 'Error: Failed to remove client\n'


def test_client_info_exception(mocker):
    mocker.patch('requests.get', return_none)
    result = TEST_CLI.invoke(main.cli, ['client', 'info', '--uid', 'test-client'])
    assert result.exit_code == 1
    assert result.output == 'Error: Failed to get client info\n'


def test_client_list_exception(mocker):
    mocker.patch('kxicli.common.get_admin_token', return_none)
    mocker.patch('requests.get', return_none)
    result = TEST_CLI.invoke(main.cli, ['client', 'list', '--username', 'test-user', '--password', 'test-pass'])
    assert result.exit_code == 1
    assert result.output == 'Error: Failed to list clients\n'
