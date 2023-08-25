import time
import pytest
import datetime
import pandas as pd
import random
from kxicli import main
from unittest.mock import ANY, call, MagicMock
from pytest_mock import MockerFixture
from kxi import DeploymentType
from kxi.auth import Authorizer
from utils import return_none
from kxicli.commands.query import query
from click.testing import CliRunner
from kxicli.resources.auth import AuthCache


@pytest.fixture()
def query_mock(mocker: MockerFixture):
    return mocker.patch("kxicli.commands.query.Query")


@pytest.fixture()
def table_pd_mock(mocker: MockerFixture):
    return mocker.patch("kxicli.commands.query.Query.Table.pd")


# Constants
HOSTNAME = "http://hostname:8082"
USAGE_MICROSERVICES = "microservices"
PROTOCOL = "http"
USER = "user"
PASSWORD = "password"
SQL = "select * from trade"
OUTPUT_FORMAT = "tabular"
CLIENT_ID = "client_id"
CLIENT_SECRET = "client_secret"

TEST_FILE_SCHEME = [
    {"name": "time", "type": "timedelta"},
    {"name": "realTime", "type": "datetime"},
    {"name": "price", "type": "float"},
    {"name": "size", "type": "long"},
]

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

@pytest.fixture
def mock_auth_functions(mocker):
    mocker.patch.object(Authorizer, 'fetch_token', return_value=MagicMock(access_token=TEST_SERVICE_ACCOUNT_TOKEN))
    mocker.patch.object(Authorizer, 'token', return_value=TEST_SERVICE_ACCOUNT_TOKEN)
    mocker.patch.object(Authorizer, 'check_cached_token', return_value=TEST_SERVICE_ACCOUNT_TOKEN)
    
    mocker.patch('kxicli.resources.auth.get_serviceaccount_token', return_none)
    

def generate_test_data(number_of_rows, cols):
    data = {}
    for col in cols:
        data[col["name"]] = []
        for _ in range(number_of_rows):
            act_value = None
            if col["type"] == "timedelta":
                act_value = (
                    f"{random.randint(10,23)}:{random.randint(10,59)}:{random.randint(10,59)}"
                )
            elif col["type"] == "datetime":
                act_value = datetime.datetime.now().isoformat()
            elif col["type"] == "float":
                act_value = str(random.random() * 10000)
            elif col["type"] == "long":
                act_value = str(random.randint(1, 10000))

            data[col["name"]].append(act_value)
    return pd.DataFrame(data)

TEST_CLI = CliRunner()
test_data = generate_test_data(10, TEST_FILE_SCHEME)


def test_query_calls_kxi_query(query_mock, mock_auth_functions):
    query_sql_mock = query_mock.sql.return_value

    result = TEST_CLI.invoke(main.cli, ['query',
                             '--hostname', HOSTNAME,
                             '--usage', USAGE_MICROSERVICES,
                             '--sql', SQL,
                             '--output-format', OUTPUT_FORMAT
    ])

    assert result.exit_code == 0
    query_mock.assert_has_calls([
        call( HOSTNAME, usage=USAGE_MICROSERVICES.upper(), realm='insights', cache=AuthCache),
        call().sql(SQL)
    ])
    
def test_query_calls_kxi_query_enterprise(query_mock, mock_auth_functions):
    query_sql_mock = query_mock.sql.return_value

    result = TEST_CLI.invoke(main.cli, ['query',
                             '--hostname', HOSTNAME,
                             '--usage', DeploymentType.ENTERPRISE,
                             '--sql', SQL,
                             '--output-format', OUTPUT_FORMAT,
                             '--client-id', CLIENT_ID,
                             '--client-secret', CLIENT_SECRET
    ])

    assert result.exit_code == 0

    query_mock.assert_has_calls([
        call( HOSTNAME, usage='ENTERPRISE', realm='insights', cache=AuthCache),
        call().sql(SQL)
    ])    

def test_query_results_tabular(query_mock, table_pd_mock):    
    query_mock.return_value.sql.return_value.pd.return_value = test_data
    
    result = TEST_CLI.invoke(main.cli, ['query',
                             '--hostname', HOSTNAME,
                             '--usage', USAGE_MICROSERVICES,
                             '--sql', SQL,
                             '--output-format', "tabular",
                             '--client-id', CLIENT_ID,
                             '--client-secret', CLIENT_SECRET
    ])

    assert result.exit_code == 0

    query_mock.assert_has_calls([
        call( HOSTNAME, usage=USAGE_MICROSERVICES.upper(), realm='insights', cache=AuthCache),
        call().sql(SQL)
    ])
    
    assert test_data.to_string(index=False) == result.output
    
def test_query_results_csv(query_mock, table_pd_mock, mock_auth_functions):
    test_data = generate_test_data(1, TEST_FILE_SCHEME)
    query_mock.return_value.sql.return_value.pd.return_value = test_data
    
    result = TEST_CLI.invoke(main.cli, ['query',
                             '--hostname', HOSTNAME,
                             '--usage', USAGE_MICROSERVICES,
                             '--sql', SQL,
                             '--output-format', "csv",
                             '--client-id', CLIENT_ID,
                             '--client-secret', CLIENT_SECRET
    ])

    assert result.exit_code == 0

    query_mock.assert_has_calls([
        call( HOSTNAME, usage=USAGE_MICROSERVICES.upper(), realm='insights', cache=AuthCache),
        call().sql(SQL)
    ])
    
    assert test_data.to_csv(index=False) == result.output
    
def test_query_results_json(query_mock, table_pd_mock, mock_auth_functions):
    test_data = generate_test_data(1, TEST_FILE_SCHEME)
    query_mock.return_value.sql.return_value.pd.return_value = test_data
    
    result = TEST_CLI.invoke(main.cli, ['query',
                             '--hostname', HOSTNAME,
                             '--usage', USAGE_MICROSERVICES,
                             '--sql', SQL,
                             '--output-format', "json",
                             '--client-id', CLIENT_ID,
                             '--client-secret', CLIENT_SECRET
    ])

    assert result.exit_code == 0

    query_mock.assert_has_calls([
        call( HOSTNAME, usage=USAGE_MICROSERVICES.upper(), realm='insights', cache=AuthCache),
        call().sql(SQL)
    ])
    
    assert test_data.to_json() == result.output
    
def test_query_results_json_records(query_mock, table_pd_mock, mock_auth_functions):
    test_data = generate_test_data(1, TEST_FILE_SCHEME)
    query_mock.return_value.sql.return_value.pd.return_value = test_data
    
    result = TEST_CLI.invoke(main.cli, ['query',
                             '--hostname', HOSTNAME,
                             '--usage', USAGE_MICROSERVICES,
                             '--sql', SQL,
                             '--output-format', "json_records",
                             '--client-id', CLIENT_ID,
                             '--client-secret', CLIENT_SECRET
    ])

    assert result.exit_code == 0

    query_mock.assert_has_calls([
        call( HOSTNAME, usage=USAGE_MICROSERVICES.upper(), realm='insights', cache=AuthCache),
        call().sql(SQL)
    ])
    
    assert test_data.to_json(orient="records", lines=True) == result.output