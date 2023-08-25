import shutil
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp

from click.testing import CliRunner

from kxicli import config
from kxicli import main
from kxicli import phrases

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

def run_config_test(func, profile, name, value, expected_result):
    config.load_config('default')
    with temp_config_file() as config_file_name:
        shutil.copyfile(config.config_file, config_file_name)
        config.config_file = config_file_name

        func(profile, name, value)

        with open(config.config_file, "r") as f:
            assert f.read() == expected_result

    # restore
    config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')
    config.load_config('default')


def test_append_config_parameter_appends_to_file_default():
    expected_result = """[default]
usage = enterprise
hostname = https://test.kx.com
namespace = test
client.id = client
client.secret = secret
auth.serviceaccount.id = test_id
auth.serviceaccount.secret = test_client_id
test-name = test-value

"""
    run_config_test(func=config.append_config, profile='default', name='test-name', value='test-value', expected_result=expected_result)


def test_append_config_parameter_appends_to_file_new_profile():
    expected_result = """[default]
usage = enterprise
hostname = https://test.kx.com
namespace = test
client.id = client
client.secret = secret
auth.serviceaccount.id = test_id
auth.serviceaccount.secret = test_client_id

[test-profile]
test-name = test-value

"""
    run_config_test(func=config.append_config, profile='test-profile', name='test-name', value='test-value', expected_result=expected_result)


def test_update_config_parameter_appends_to_file_default():
    expected_result = """[default]
usage = enterprise
hostname = https://test.kx.com
namespace = test
client.id = client
client.secret = secret
auth.serviceaccount.id = test_id
auth.serviceaccount.secret = test_client_id
test-name = test-value

"""
    run_config_test(func=config.update_config, profile='default', name='test-name', value='test-value', expected_result=expected_result)


def test_update_config_updates_existing_option():
    expected_result = """[default]
usage = enterprise
hostname = https://test.kx.com
namespace = test
client.id = client
client.secret = test-value
auth.serviceaccount.id = test_id
auth.serviceaccount.secret = test_client_id

"""
    run_config_test(func=config.update_config, profile='default', name='client.secret', value='test-value', expected_result=expected_result)


def test_update_config_has_no_effect_on_unchanged_option():
    expected_result = """[default]
usage = enterprise
hostname = https://test.kx.com
namespace = test
client.id = client
client.secret = secret
auth.serviceaccount.id = test_id
auth.serviceaccount.secret = test_client_id

"""
    run_config_test(func=config.update_config, profile='default', name='client.secret', value='secret', expected_result=expected_result)


def test_configure_output_is_correct():
    with temp_config_file() as config_file_name:
        shutil.copyfile(config.config_file, config_file_name)
        config.config_file = config_file_name
        runner = CliRunner()
        with runner.isolated_filesystem():
            user_input = (
                'enterprise\n'
                'https://test.kx.com\n'
                'test\n'
                'test_id\n'
                'test_client_id\n'
                'test_client_id\n'
            )

            result = runner.invoke(main.cli, ['configure'], input=user_input)

        expected_output = (
                'Profile type (enterprise, microservices) [enterprise]: enterprise\n'
                'Hostname [https://test.kx.com]: https://test.kx.com\n'
                'Namespace [test]: test\n'
                'Service account ID [test_id]: test_id\n'
                f'Service account Secret (input hidden): \n{phrases.password_reenter}: \n'
                'CLI successfully configured, configuration stored in ' + config.config_file + '\n'
        )

        assert result.exit_code == 0
        assert result.output == expected_output
        with open(config.config_file, "r") as f:
            assert f.read() == """[default]
usage = enterprise
hostname = https://test.kx.com
namespace = test
client.id = client
client.secret = secret
auth.serviceaccount.id = test_id
auth.serviceaccount.secret = test_client_id

"""
    config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')



def test_microservices_configure_output_is_correct():
    config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config-microservices')
    with temp_config_file(file_name='test-cli-config-microservices') as config_file_name:
        shutil.copyfile(config.config_file, config_file_name)
        config.config_file = config_file_name
        runner = CliRunner()
        with runner.isolated_filesystem():
            user_input = (
                'microservices\n'
                'https://test.kx.com\n'
                '5010\n'
            )

            result = runner.invoke(main.cli, ['configure'], input=user_input)

        expected_output = (
                'Profile type (enterprise, microservices) [microservices]: microservices\n'
                'Hostname [https://test.kx.com]: https://test.kx.com\n'
                'TP Port [5010]: 5010\n'
                'CLI successfully configured, configuration stored in ' + config.config_file + '\n'
        )

        assert result.exit_code == 0
        assert expected_output == result.output
        with open(config.config_file, "r") as f:
            assert f.read() == """[default]
usage = microservices
hostname = https://test.kx.com
tp_port = 5010

"""
    config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')
