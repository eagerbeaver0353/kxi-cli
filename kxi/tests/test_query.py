import responses
from click.testing import CliRunner
from kxi import main

test_host='https://test.kx.com'

@responses.activate
def test_query_returns_empty_payload():
    """Test that empty responses returned 'Emtpy payload'"""
    runner = CliRunner()

    # Mock the necessary endpoint
    responses.add(responses.POST,
                test_host+'/auth/realms/insights/protocol/openid-connect/token',
                json={'access_token': 'token'},
                status=200)
    responses.add(responses.POST,
                test_host+'/servicegateway/kxi/getData',
                json=[[],[]],
                status=200)

    result = runner.invoke(main.cli, ['query', '--table', 'trace'])
    assert result.exit_code == 0
    assert result.output == 'Empty payload\n'
