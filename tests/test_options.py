import click
import io
import os
import pytest
from kxicli import options
from kxicli import common
from kxicli import phrases
from utils import return_true, return_false

# Constants for common import paths
SYS_STDIN = 'sys.stdin'

config_file_startup = str(common.config.config_dir_path / 'cli-config')
common.config.config_file = os.path.dirname(__file__) + '/files/test-cli-config'
common.config.load_config("default")


def mocked_k8s_list_empty_config():
    return ([], {'context': ()})


def mock_k8s_list_empty_config(mocker):
    mocker.patch('kubernetes.config.list_kube_config_contexts', mocked_k8s_list_empty_config)


def test_get_namespace(mocker):
    # Result retrived from kube context
    assert options.get_namespace() == 'test'
    mocker.patch('kubernetes.config.list_kube_config_contexts', mocked_k8s_list_empty_config)
    assert options.get_namespace() == None


def test_options_namespace_decorator():
    assert options.namespace.decorator().func == click.option
    assert options.namespace.decorator().args == ('--namespace',)
    assert options.namespace.decorator().keywords['help'] == 'Kubernetes namespace'
    assert options.namespace.decorator().keywords['default']() == 'test'


def test_options_namespace_prompt_with_k8s_context(mocker):
    # Result retrieved from --namespace command line option or default from kube context when provided
    assert options.namespace.prompt('test-namespace-from-command-line') == 'test-namespace-from-command-line'
    # Result retrieved from kube context
    assert options.namespace.prompt('test') == 'test'


def test_options_namespace_prompt_prompts_user_without_k8s_context(capsys, mocker, monkeypatch):
    # When context is not set, assert that user is prompted in an interactive session
    mock_k8s_list_empty_config(mocker)
    mocker.patch('kxicli.options._is_interactive_session', return_true)
    monkeypatch.setattr(SYS_STDIN, io.StringIO('test-namespace-from-prompt'))
    assert options.namespace.prompt() == 'test-namespace-from-prompt'
    assert capsys.readouterr().out == '\nPlease enter a namespace to run in [test]: '


def test_options_namespace_prompt_non_interactrive_without_k8s_context(mocker):
    # When context is not set, assert that value from cli-config is used
    mock_k8s_list_empty_config(mocker)
    mocker.patch('kxicli.options._is_interactive_session', return_false)
    common.config.config['default']['namespace'] = 'test-namespace-from-config'
    assert options.namespace.prompt() == 'test-namespace-from-config'
    # When neither context nor cli-config is set, assert that default is used
    common.config.config['default'].pop('namespace')
    assert options.namespace.prompt() == 'kxi'
    common.config.load_config("default")


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
    assert options.filepath.decorator().args == ('--filepath',)
    filepath_dict = options.filepath.decorator().keywords
    filepath_dict.pop('type')
    assert filepath_dict == {'help': 'Values file to install with'}
    assert type(options.filepath.decorator().keywords['type']) == click.Path


def test_options_chart_repo_name_decorator():
    assert options.chart_repo_name.decorator().func == click.option
    assert options.chart_repo_name.decorator().args == ('--chart-repo-name',)
    assert options.chart_repo_name.decorator().keywords == {'help': 'Name for chart repository'}


def test_options_chart_repo_name_forced_decorator():
    assert options.chart_repo_name_forced.decorator().func == click.option
    assert options.chart_repo_name_forced.decorator().args == ('--chart-repo-name',)
    assert options.chart_repo_name_forced.decorator().keywords == {'help': 'Name for chart repository', 'default': 'kx-insights'}


def test_options_chart_repo_username_decorator():
    assert options.chart_repo_username.decorator().func == click.option
    assert options.chart_repo_username.decorator().args == ('--chart-repo-username',)
    assert options.chart_repo_username.decorator().keywords == {'help': 'Username for the chart repository'}


def test_options_chart_repo_name_decorator():
    assert options.chart_repo_name.decorator().func == click.option
    assert options.chart_repo_name.decorator().args == ('--chart-repo-name',)
    assert options.chart_repo_name.decorator().keywords == {'help': 'Name for chart repository'}


def test_options_chart_repo_username_prompt(capsys, mocker, monkeypatch):
    mocker.patch('kxicli.options._is_interactive_session', return_false)
    # Result retrieved from --chart-repo-username command line option when provided
    assert options.chart_repo_username.prompt('test-repo-user') == 'test-repo-user'

    # Exception is raised when no tty is attached
    with pytest.raises(Exception) as e:
        options.chart_repo_username.prompt()
    assert isinstance(e.value, click.ClickException)
    assert f"Could not find expected option. Please set command line argument --chart-repo-username or configuration value chart.repo.username in config file {config_file_startup}" in e.value.message

    # Result retrieved from config when entry exists
    common.config.config['default']['chart.repo.username'] = 'test-repo-user-from-config'
    assert options.chart_repo_username.prompt() == 'test-repo-user-from-config'

    # Assert that user is prompted in an interactive session
    mocker.patch('kxicli.options._is_interactive_session', return_true)    
    monkeypatch.setattr(SYS_STDIN, io.StringIO('test-repo-user-from-prompt'))
    assert options.chart_repo_username.prompt() == 'test-repo-user-from-prompt'
    assert capsys.readouterr().out == phrases.chart_user + ' [test-repo-user-from-config]: '

    # Assert that user is prompted with a custom message in an interactive session
    monkeypatch.setattr(SYS_STDIN, io.StringIO('test-repo-user-from-custom-prompt'))
    assert options.chart_repo_username.prompt(prompt_message='A custom prompt message') == 'test-repo-user-from-custom-prompt'
    assert capsys.readouterr().out == 'A custom prompt message [test-repo-user-from-config]: '

    common.config.load_config("default")


def test_options_chart_repo_password_prompt(mocker):
    mocker.patch('kxicli.options._is_interactive_session', return_false)

    # Exception is raised when no tty is attached
    with pytest.raises(Exception) as e:
        options.chart_repo_password.prompt()
    assert isinstance(e.value, click.ClickException)
    assert f"Could not find expected option. Please set configuration value chart.repo.password in config file {config_file_startup}" in e.value.message

    # Result retrieved from config when entry exists
    common.config.config['default']['chart.repo.password'] = 'test-repo-password-from-config'
    assert options.chart_repo_password.prompt() == 'test-repo-password-from-config'

    # Assert that user is prompted in an interactive session
    mocker.patch('kxicli.options._is_interactive_session', return_true)
    mock = mocker.patch('click.prompt', return_value='test-repo-password-from-prompt')
    assert options.chart_repo_password.prompt() == 'test-repo-password-from-prompt'
    assert mock.call_count == 2

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
    mocker.patch('kxicli.options._is_interactive_session', return_false)
    # Result retrieved from --hostname command line option when provided
    assert options.hostname.prompt('hostname-from-command-line') == 'hostname-from-command-line'
    # Result retrieved from config when entry exists. Retrieved from files/test-cli-config
    assert options.hostname.prompt() == 'https://test.kx.com'

    # Remove hostname entry from config.
    common.config.config['default'].pop('hostname')
    # Exception is raised when no tty is attached
    with pytest.raises(Exception) as e:
        options.hostname.prompt()
    assert isinstance(e.value, click.ClickException)
    assert f"Could not find expected option. Please set command line argument --hostname or configuration value hostname in config file {config_file_startup}" in e.value.message

    # Assert that user is prompted for ingress host in an interactive session
    mocker.patch('kxicli.options._is_interactive_session', return_true)    
    monkeypatch.setattr(SYS_STDIN, io.StringIO('a-new-ingress-host'))
    res = options.hostname.prompt()
    assert res == 'a-new-ingress-host'
    assert capsys.readouterr().out == "Please enter the hostname for the installation: "
    common.config.load_config('default')


def test_options_filepath_prompt():
    # Result retrieved from --filepath command line option when provided
    assert options.filepath.prompt('a-new-filepath-name.yaml') == 'a-new-filepath-name.yaml'
    # Exception is raised when no tty is attached
    with pytest.raises(Exception) as e:
        options.filepath.prompt()
    assert isinstance(e.value, click.ClickException)
    assert f'Could not find expected option. Please set command line argument --filepath or configuration value install.filepath in config file {config_file_startup}' in e.value.message

