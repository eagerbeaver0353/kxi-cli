import pytest
import importlib
import json
import sys
from unittest.mock import ANY, call, MagicMock, patch
from pathlib import Path
from pytest_mock import MockerFixture
from click.testing import CliRunner
import kxicli.main



@pytest.fixture()
def dbpublisher_mock(mocker: MockerFixture):
    return mocker.patch("kxicli.commands.publish.DBPublisher")


# Constants
HOSTNAME_FULL = "http://hostname"
HOSTNAME_HOST = "hostname"
PORT = 5010
USER = "user"
PASSWORD = "password"
CHUNK_SIZE = 100
CSV_FILENAME = "/test/testfile.csv"
TARGET_TABLE = "trade"
FILE_FORMAT = "csv"
TYPE_MAP = '{"time": "timedelta", "realTime": "datetime", "price": "numeric"}'

TEST_CLI = CliRunner()

def test_publish_calls_dbpublisher(dbpublisher_mock):
    
    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config-microservices')
    
    result = TEST_CLI.invoke(kxicli.main.cli, [
                            'publish',
                            '--hostname', HOSTNAME_FULL,
                            '--port', PORT,
                            '--data', CSV_FILENAME,
                            '--table', TARGET_TABLE,
                            '--file-format', FILE_FORMAT,
                            '--type-map', TYPE_MAP])

    assert result.exit_code == 0

    dbpublisher_mock.assert_has_calls([
        call(host=HOSTNAME_HOST, port=PORT),
        call().__enter__(),
        call().__enter__().publish(CSV_FILENAME, TARGET_TABLE, FILE_FORMAT, json.loads(TYPE_MAP)),
        call().__exit__(None, None, None)
    ])    
   
    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')
