import os
from click.testing import CliRunner
from kxi import main
from kxi import config

config.config_file = os.path.dirname(__file__) + '/test-cli-config'

def test_configure_output_is_correct():
    runner = CliRunner()
    with runner.isolated_filesystem():
        user_input = (
            'https://test.kx.com\n'
            'test\n'
            'client\n'
            'secret\n'
        )

        result = runner.invoke(main.cli, ['configure'], input=user_input)


    expected_output = (
        'Hostname [https://test.kx.com]: https://test.kx.com\n'
        'Namespace [test]: test\n'
        'Client ID [client]: client\n'
        'Client Secret (input hidden): \n'
        'CLI successfully configured, configuration stored in ' + config.config_file + '\n'
    )

    assert result.exit_code == 0
    assert result.output == expected_output
