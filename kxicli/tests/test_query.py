import responses
import pytest
from click.testing import CliRunner
from kxicli import main

test_host='https://test.kx.com'

@pytest.mark.skip(reason="'kxi query' is disabled until KXI-6201 is implemented")
@responses.activate
def test_query_returns_empty_payload():
    """Test that empty responses returned 'Empty payload'"""
    runner = CliRunner()

    # Mock the necessary endpoint
    responses.add(responses.POST,
                f'{test_host}/auth/realms/insights/protocol/openid-connect/token',
                json={'access_token': 'token'},
                status=200)
    responses.add(responses.POST,
                test_host+'/servicegateway/kxi/getData',
                json=[[],[]],
                status=200)

    result = runner.invoke(main.cli, ['query', '--table', 'trace'])
    assert result.exit_code == 0
    assert result.output == 'Empty payload\n'
