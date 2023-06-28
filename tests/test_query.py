import pytest
import datetime
import pandas as pd
import random
from kxicli import main
from unittest.mock import ANY, call, MagicMock
from pytest_mock import MockerFixture
from kxi import DeploymentType

from kxicli.commands.query import query
from click.testing import CliRunner


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


def test_query_calls_kxi_query(query_mock):
    query_sql_mock = query_mock.sql.return_value

    result = TEST_CLI.invoke(main.cli, ['query',
                             '--hostname', HOSTNAME,
                             '--usage', USAGE_MICROSERVICES,
                             '--sql', SQL,
                             '--output-format', OUTPUT_FORMAT,
                             '--client-id', CLIENT_ID,
                             '--client-secret', CLIENT_SECRET
    ])

    assert result.exit_code == 0

    query_mock.assert_has_calls([
        call( HOSTNAME, usage=USAGE_MICROSERVICES.upper(), client_id=CLIENT_ID, client_secret=CLIENT_SECRET),
        call().sql(SQL)
    ])
    
def test_query_calls_kxi_query_enterprise(query_mock):
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
        call(HOSTNAME, usage=DeploymentType.ENTERPRISE.value.upper(), client_id=CLIENT_ID, client_secret=CLIENT_SECRET),
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
        call(HOSTNAME, usage=USAGE_MICROSERVICES.upper(), client_id=CLIENT_ID, client_secret=CLIENT_SECRET),
        call().sql(SQL)
    ])
    
    assert test_data.to_string(index=False) == result.output
    
def test_query_results_csv(query_mock, table_pd_mock):
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
        call(HOSTNAME, usage=USAGE_MICROSERVICES.upper(), client_id=CLIENT_ID, client_secret=CLIENT_SECRET),
        call().sql(SQL)
    ])
    
    assert test_data.to_csv(index=False) == result.output
    
def test_query_results_json(query_mock, table_pd_mock):
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
        call(HOSTNAME, usage=USAGE_MICROSERVICES.upper(), client_id=CLIENT_ID, client_secret=CLIENT_SECRET),
        call().sql(SQL)
    ])
    
    assert test_data.to_json() == result.output
    
def test_query_results_json_records(query_mock, table_pd_mock):
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
        call(HOSTNAME, usage=USAGE_MICROSERVICES.upper(), client_id=CLIENT_ID, client_secret=CLIENT_SECRET),
        call().sql(SQL)
    ])
    
    assert test_data.to_json(orient="records", lines=True) == result.output