import click
import io
import os
import pytest
from kxicli import options
from kxicli import common
from kxicli import phrases
import utils

# Constants for common import paths
SYS_STDIN = 'sys.stdin'

test_cli_config = os.path.dirname(__file__) + '/files/test-cli-config'
common.config.config_file = test_cli_config
common.config.load_config("default")


def mocked_k8s_list_empty_config():
    return ([], {'context': ()})


def mock_k8s_list_empty_config(mocker):
    mocker.patch('kubernetes.config.list_kube_config_contexts', mocked_k8s_list_empty_config)


def test_get_namespace(mocker):
    # Result retrived from kube context
    assert options.get_namespace() == utils.namespace()
    mocker.patch('kubernetes.config.list_kube_config_contexts', mocked_k8s_list_empty_config)
    assert options.get_namespace() == None


def test_print_option_source(capsys):
    options.print_option_source('Print option source with value', 'test_value', False, False)
    assert capsys.readouterr().err == 'Print option source with value: test_value\n'

    options.print_option_source('Print option source but hide password value', 'test_value', True, False)
    assert capsys.readouterr().err == 'Print option source but hide password value\n'
    
    options.print_option_source('Print option source with non-string value', 1234, False, False)
    assert capsys.readouterr().err == 'Print option source with non-string value: 1234\n'

    options.print_option_source('Silent option source', 'test_value', False, True)
    assert capsys.readouterr().err == ''


def test_print_cmd_line_option(capsys):
    options.print_cmd_line_option('Print value from command-line without default', 'a-test-value', False, None, False)
    assert capsys.readouterr().err == 'Print value from command-line without default: a-test-value\n'

    options.print_cmd_line_option('Print value from command-line without default, hiding password value', 'a-test-value', True, None, False)
    assert capsys.readouterr().err == 'Print value from command-line without default, hiding password value\n'

    options.print_cmd_line_option('Print value from command-line with None default lambda', 'a-test-value', False, lambda: None, False)
    assert capsys.readouterr().err == 'Print value from command-line with None default lambda: a-test-value\n'

    options.print_cmd_line_option('Print value from command-line with None default lambda, hiding password value', 'a-test-value', True, lambda: None, False)
    assert capsys.readouterr().err == 'Print value from command-line with None default lambda, hiding password value\n'

    options.print_cmd_line_option('Hide value from command-line with default value', 'a-test-value', False, 'a-default-value', False)
    assert capsys.readouterr().err == ''

    options.print_cmd_line_option('Hide value from command-line with default value as password', 'a-test-value', True, 'a-default-value', False)
    assert capsys.readouterr().err == ''

    options.print_cmd_line_option('Hide value from command-line with default lambda, not as password', 'a-test-value', False, lambda: 'a-default-value', False)
    assert capsys.readouterr().err == ''

    options.print_cmd_line_option('Hide value from command-line with default lambda as password', 'a-test-value', True, lambda: 'a-default-value', False)
    assert capsys.readouterr().err == ''

    options.print_cmd_line_option('Hide value from command-line when silent', 'a-test-value', False, 'a-default-value', True)
    assert capsys.readouterr().err == ''

def test_get_prompt_message():
    test_option = options.Option(
        '--test-option',
        config_name = 'test.option',
        prompt_message='a test prompt message from option definition'
    )
    assert options.get_prompt_message(test_option, 'prompt message from arg') == 'prompt message from arg'
    assert options.get_prompt_message(test_option, '') == 'a test prompt message from option definition'


def test_interactive_prompt(capsys, monkeypatch):
    monkeypatch.setattr(SYS_STDIN, io.StringIO('test-value'))
    assert options.interactive_prompt('A prompt message not as password, without default', False, None) == 'test-value'
    assert capsys.readouterr().out == 'A prompt message not as password, without default: '

    monkeypatch.setattr(SYS_STDIN, io.StringIO('test-value'))
    assert options.interactive_prompt('A prompt message not as password, with default', False, 'default-value') == 'test-value'
    assert capsys.readouterr().out == 'A prompt message not as password, with default [default-value]: '


def test_prompt_error_message():
    test_option = options.Option('--test-option', config_name = 'test.option')
    msg = options.prompt_error_message(options.Option('--test-option', config_name = 'test.option')) 
    assert msg == f'Could not find expected option. Please set command line argument (\'--test-option\',) or configuration value test.option in config file {common.config.config_file}'

    msg = options.prompt_error_message(
        options.Option('--test-option')
        )
    assert msg == 'Could not find expected option. Please set command line argument (\'--test-option\',)'

    msg = options.prompt_error_message(
        options.Option(config_name = 'test.option')
        )
    
    assert msg == f'Could not find expected option. Please set configuration value test.option in config file {common.config.config_file}'

    msg =  options.prompt_error_message(
        options.Option()
        ) 
    assert msg == 'Could not find expected option.'


def test_options_generate_password():
    test_pass = options.generate_password()
    assert len(test_pass) == 10
    assert type(test_pass) == str
    assert not test_pass == options.generate_password()


def test_options_namespace_decorator():
    assert options.namespace.decorator().func == click.option
    assert options.namespace.decorator().args == ('-n', '--namespace',)
    assert options.namespace.decorator().keywords['help'] == 'Kubernetes namespace'
    assert options.namespace.decorator().keywords['default']() == utils.namespace()


def test_options_namespace_prompt_with_k8s_context(mocker):
    # Result retrieved from --namespace command line option or default from kube context when provided
    assert options.namespace.prompt('test-namespace-from-command-line') == 'test-namespace-from-command-line'
    # Result retrieved from kube context
    assert options.namespace.prompt('test') == 'test'


def test_options_namespace_prompt_non_interactrive_without_k8s_context(mocker):
    # When context is not set, assert that value from cli-config is used
    mock_k8s_list_empty_config(mocker)
    mocker.patch('kxicli.common.is_interactive_session', utils.return_false)
    common.config.config['default']['namespace'] = 'test-namespace-from-config'
    assert options.namespace.prompt() == 'test-namespace-from-config'
    # When neither context nor cli-config is set, assert that default is used
    common.config.config['default'].pop('namespace')
    assert options.namespace.prompt() == 'kxi'
    common.config.load_config("default")


def test_options_namespace_prompt_prompts_user_without_k8s_context(capsys, mocker, monkeypatch):
    # When neither context nor cli-config is set, assert user is prompted
    mock_k8s_list_empty_config(mocker)
    common.config.config['default'].pop('namespace')
    mocker.patch('kxicli.common.is_interactive_session', utils.return_true)
    monkeypatch.setattr(SYS_STDIN, io.StringIO('test-namespace-from-prompt'))
    assert options.namespace.prompt() == 'test-namespace-from-prompt'
    assert capsys.readouterr().out == '\nPlease enter a namespace to run in [kxi]: '


def test_options_version_decorator():
    assert options.version.decorator().func == click.option
    assert options.version.decorator().args == ('--version',)
    assert options.version.decorator().keywords == {'help': 'Version to install', 'required': True}


def test_options_operator_version_decorator():
    assert options.operator_version.decorator().func == click.option
    assert options.operator_version.decorator().args == ('--operator-version',)
    assert options.operator_version.decorator().keywords == {'help': 'Version of the operator to install', 'type': click.STRING}


def test_options_filepath_decorator():
    assert options.filepath.decorator().func == click.option
    assert options.filepath.decorator().args == ('-f', '--filepath',)
    filepath_dict = options.filepath.decorator().keywords
    filepath_dict.pop('type')
    assert filepath_dict == {'help': 'Values file to install with'}
    assert type(options.filepath.decorator().keywords['type']) == click.Path


def test_options_chart_repo_name_decorator():
    assert options.chart_repo_name.decorator().func == click.option
    assert options.chart_repo_name.decorator().args == ('--chart-repo-name',)
    assert options.chart_repo_name.decorator().keywords == {'help': 'Name for chart repository'}


def test_options_chart_repo_username_decorator():
    assert options.chart_repo_username.decorator().func == click.option
    assert options.chart_repo_username.decorator().args == ('--chart-repo-username',)
    assert options.chart_repo_username.decorator().keywords == {'help': 'Username for the chart repository', 'hidden': True}


def test_assembly_backup_filepath_decorator():
    assert options.assembly_backup_filepath.decorator().func == click.option
    assert options.assembly_backup_filepath.decorator().args == ('--assembly-backup-filepath',)
    assert options.assembly_backup_filepath.decorator().keywords == {'help': 'Filepath to store state of running assemblies'}


def test_options_chart_repo_username_prompt_from_command_line():
    # Result retrieved from --chart-repo-username command line option when provided
    assert options.chart_repo_username.prompt('test-repo-user') == 'test-repo-user'


def test_options_chart_repo_username_prompt_retrieves_from_config_in_non_interactive(mocker):
    # Result retrieved from config when entry exists
    mocker.patch('kxicli.common.is_interactive_session', utils.return_false)
    common.config.config['default']['chart.repo.username'] = 'test-repo-user-from-config'
    assert options.chart_repo_username.prompt() == 'test-repo-user-from-config'
    common.config.load_config("default")


def test_options_chart_repo_username_prompts_in_interactive(capsys, mocker, monkeypatch):
    # Assert that user is prompted in an interactive session when no config entry exists
    mocker.patch('kxicli.common.is_interactive_session', utils.return_true)
    monkeypatch.setattr(SYS_STDIN, io.StringIO('test-repo-user-from-prompt'))
    assert options.chart_repo_username.prompt() == 'test-repo-user-from-prompt'
    message = capsys.readouterr()
    assert message.out == phrases.chart_user + ': '


def test_options_chart_repo_username_prompt_errors_in_non_interactive(mocker):
    # Exception is raised when no tty is attached, and no entry exists in config
    mocker.patch('kxicli.common.is_interactive_session', utils.return_false)
    with pytest.raises(Exception) as e:
        options.chart_repo_username.prompt()
    assert isinstance(e.value, click.ClickException)
    assert f"Could not find expected option. Please set command line argument (\'--chart-repo-username\',) or configuration value chart.repo.username in config file {common.config.config_file}" in e.value.message


def test_options_chart_repo_username_prompt_custom_message(capsys, mocker, monkeypatch):
    # Assert that user is prompted with a custom message in an interactive session
    mocker.patch('kxicli.common.is_interactive_session', utils.return_true)
    monkeypatch.setattr(SYS_STDIN, io.StringIO('test-repo-user-from-custom-prompt'))
    assert options.chart_repo_username.prompt(prompt_message='A custom prompt message') == 'test-repo-user-from-custom-prompt'
    assert capsys.readouterr().out == 'A custom prompt message: '


def test_options_chart_repo_password_prompt(mocker):
    mocker.patch('kxicli.common.is_interactive_session', utils.return_false)

    # Exception is raised when no tty is attached
    with pytest.raises(Exception) as e:
        options.chart_repo_password.prompt()
    assert isinstance(e.value, click.ClickException)
    assert f"Could not find expected option. Please set configuration value chart.repo.password in config file {common.config.config_file}" in e.value.message

    # Assert that user is prompted in an interactive session
    mocker.patch('kxicli.common.is_interactive_session', utils.return_true)
    mock = mocker.patch('click.prompt', return_value='test-repo-password-from-prompt')
    assert options.chart_repo_password.prompt() == 'test-repo-password-from-prompt'
    assert mock.call_count == 2

    # Result retrieved from config when entry exists
    common.config.config['default']['chart.repo.password'] = 'test-repo-password-from-config'
    assert options.chart_repo_password.prompt() == 'test-repo-password-from-config'

    common.config.load_config("default")


def test_options_output_file_decorator():
    assert options.output_file.decorator().func == click.option
    assert options.output_file.decorator().args == ('--output-file',)
    options.output_file.decorator().keywords['default']() == 'values.yaml'
    assert options.output_file.decorator().keywords['help'] == 'Name for the generated values file'


def test_options_output_file_prompt():
    # Result retrieved from --output-file command line option when provided
    assert options.output_file.prompt('a-test-output-file-name.yaml') == 'a-test-output-file-name.yaml'
    # Result retrieved from default
    assert options.output_file.prompt() == 'values.yaml'
    # Result retrieved from config when entry exists
    common.config.config['default']['install.outputFile'] = 'another-test-output-file-name.yaml'
    assert options.output_file.prompt() == 'another-test-output-file-name.yaml'
    common.config.load_config("default")


def test_options_hostname_prompt(capsys, mocker, monkeypatch):
    # Result retrieved from --hostname command line option when provided
    assert options.hostname.prompt('hostname-from-command-line') == 'hostname-from-command-line'
    # Result retrieved from config when entry exists. Retrieved from files/test-cli-config
    assert options.hostname.prompt() == 'https://test.kx.com'


def test_options_hostname_prompts_in_interactive(capsys, mocker, monkeypatch):
    # Assert that user is prompted for ingress host in an interactive session when hostname is not configured
    mocker.patch('kxicli.common.is_interactive_session', utils.return_true)
    # Remove hostname entry from config.
    common.config.config['default'].pop('hostname')
    monkeypatch.setattr(SYS_STDIN, io.StringIO('a-new-ingress-host'))
    res = options.hostname.prompt()
    assert res == 'a-new-ingress-host'
    assert capsys.readouterr().out == "Please enter the hostname for the installation: "
    common.config.load_config('default')


def test_options_hostname_prompt_returns_error_in_non_interactive(mocker):
    # Assert that error is returned in an interactive session when hostname is not configured
    mocker.patch('kxicli.common.is_interactive_session', utils.return_false)
    # Remove hostname entry from config.
    common.config.config['default'].pop('hostname')
    # Exception is raised when no tty is attached
    with pytest.raises(Exception) as e:
        options.hostname.prompt()
    assert isinstance(e.value, click.ClickException)
    assert f"Could not find expected option. Please set command line argument (\'--hostname\', \'--ingress-host\') or configuration value hostname in config file {common.config.config_file}" in e.value.message
    common.config.load_config("default")


def test_options_filepath_prompt():
    # Result retrieved from --filepath command line option when provided
    assert options.filepath.prompt('a-new-filepath-name.yaml') == 'a-new-filepath-name.yaml'
    # Exception is raised when no tty is attached
    with pytest.raises(Exception) as e:
        options.filepath.prompt()
    assert isinstance(e.value, click.ClickException)
    assert f'Could not find expected option. Please set command line argument (\'-f\', \'--filepath\') or configuration value install.filepath in config file {common.config.config_file}' in e.value.message

