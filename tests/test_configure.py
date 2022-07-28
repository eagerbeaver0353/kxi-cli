import shutil
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp

from click.testing import CliRunner

from kxicli import config
from kxicli import main

config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')


@contextmanager
def temp_config_file(prefix: str = 'kxicli-config-', file_name='test-cli-config'):
    dir_name: str = str()
    inited: bool = False
    try:
        dir_name = mkdtemp(prefix=prefix)
        inited = True
        output_file_name = str(Path(dir_name).joinpath(file_name))
        yield output_file_name
    finally:
        if inited:
            shutil.rmtree(dir_name)


def test_append_config_parameter_appends_to_file_default():
    config.load_config('default')
    with temp_config_file() as config_file_name:
        shutil.copyfile(config.config_file, config_file_name)
        config.config_file = config_file_name

        config.append_config(profile='default', name='test-name', value='test-value')

        with open(config.config_file, "r") as f:
            assert f.read() == """[default]
hostname = https://test.kx.com
namespace = test
client.id = client
client.secret = secret
test-name = test-value

"""
    # restore
    config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')
    config.load_config('default')


def test_append_config_parameter_appends_to_file_new_profile():
    config.load_config('default')
    with temp_config_file() as config_file_name:
        shutil.copyfile(config.config_file, config_file_name)
        config.config_file = config_file_name

        config.append_config(profile='test-profile', name='test-name', value='test-value')

        with open(config.config_file, "r") as f:
            assert f.read() == """[default]
hostname = https://test.kx.com
namespace = test
client.id = client
client.secret = secret

[test-profile]
test-name = test-value

"""
    # restore
    config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')
    config.load_config('default')


def test_configure_output_is_correct():
    with temp_config_file() as config_file_name:
        shutil.copyfile(config.config_file, config_file_name)
        config.config_file = config_file_name
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
        with open(config.config_file, "r") as f:
            assert f.read() == """[default]
hostname = https://test.kx.com
namespace = test
client.id = client
client.secret = secret

"""
    config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')
