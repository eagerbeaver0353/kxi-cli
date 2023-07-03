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



@pytest.fixture(autouse=True)
def default_config():
    test_cli_config = os.path.dirname(__file__) + '/files/test-cli-config'
    common.config.config_file = test_cli_config
    common.config.load_config("default")
    yield
    common.config.load_config("default")


def test_get_namespace(mocker, k8s):
    # Result retrived from kube context
    assert options.get_namespace() == utils.namespace()
    k8s.config.namespace = None
    assert options.get_namespace() == None


@pytest.mark.parametrize("args, err", [
    (('Print option source with value', 'test_value', False, False), 'Print option source with value: test_value\n'),
    (('Print option source but hide password value', 'test_value', True, False), 'Print option source but hide password value\n'),
    (('Print option source with non-string value', 1234, False, False), 'Print option source with non-string value: 1234\n'),
    (('Silent option source', 'test_value', False, True), "")
])
def test_print_option_source(capsys, args, err):
    options.print_option_source(*args)
    assert capsys.readouterr().err == err


@pytest.mark.parametrize("args, err", [
    (('Print value from command-line without default', 'a-test-value', False, None, False), 'Print value from command-line without default: a-test-value\n'),
    (('Print value from command-line without default, hiding password value', 'a-test-value', True, None, False), 'Print value from command-line without default, hiding password value\n'),
    (('Print value from command-line with None default lambda', 'a-test-value', False, lambda: None, False), "Print value from command-line with None default lambda: a-test-value\n"),
    (('Print value from command-line with None default lambda, hiding password value', 'a-test-value', True, lambda: None, False), "Print value from command-line with None default lambda, hiding password value\n"),
    (('Hide value from command-line with default value', 'a-test-value', False, 'a-default-value', False), ""),
    (('Hide value from command-line with default value as password', 'a-test-value', True, 'a-default-value', False), ""),
    (('Hide value from command-line with default lambda, not as password', 'a-test-value', False, lambda: 'a-default-value', False), ""),
    (('Hide value from command-line with default lambda as password', 'a-test-value', True, lambda: 'a-default-value', False), ""),
    (('Hide value from command-line when silent', 'a-test-value', False, 'a-default-value', True), "")
])
def test_print_cmd_line_option(capsys, args, err):
    options.print_cmd_line_option(*args)
    assert capsys.readouterr().err == err


@pytest.mark.parametrize("arg", ["", "prompt message from arg"])
def test_get_prompt_message(arg):
    prompt_message = 'a test prompt message from option definition'
    test_option = options.Option(
        '--test-option',
        config_name = 'test.option',
        prompt_message = prompt_message
    )
    expected = arg or prompt_message
    assert options.get_prompt_message(test_option, arg) == expected


@pytest.mark.parametrize("prompt, default",  [
    ("A prompt message not as password, without default", "default-value"),
    ("A prompt message not as password, with default", None)
])
def test_interactive_prompt(capsys, monkeypatch, prompt, default):
    monkeypatch.setattr(SYS_STDIN, io.StringIO('test-value'))
    assert options.interactive_prompt(prompt, False, default) == 'test-value'
    out = prompt
    if default:
        out += f" [{default}]"
    assert capsys.readouterr().out == f'{out}: '


def test_prompt_error_message_cli_config():
    msg = options.prompt_error_message(options.Option('--test-option', config_name = 'test.option'))
    assert msg == f'Could not find expected option. Please set command line argument (\'--test-option\',) or configuration value test.option in config file {common.config.config_file}'


def test_prompt_error_message_cli():
    msg = options.prompt_error_message(
        options.Option('--test-option')
        )
    assert msg == 'Could not find expected option. Please set command line argument (\'--test-option\',)'


def test_prompt_error_message_config():
    msg = options.prompt_error_message(
        options.Option(config_name = 'test.option')
        )
    assert msg == f'Could not find expected option. Please set configuration value test.option in config file {common.config.config_file}'


def test_prompt_error_message():
    msg =  options.prompt_error_message(
        options.Option()
        )
    assert msg == 'Could not find expected option.'


def test_options_generate_password():
    test_pass = options.generate_password()
    assert len(test_pass) == 10
    assert type(test_pass) == str
    assert not test_pass == options.generate_password()


def test_options_namespace_decorator_func(k8s):
    assert options.namespace.decorator().func == click.option
    

def test_options_namespace_decorator_args(k8s):
    assert options.namespace.decorator().args == ('-n', '--namespace',)
    
    
def test_options_namespace_decorator_keywords_help(k8s):
    assert options.namespace.decorator().keywords['help'] == 'Kubernetes namespace'
    
    
def test_options_namespace_decorator_keywords_default(k8s):
    assert options.namespace.decorator().keywords['default']() == utils.namespace()


def test_options_namespace_prompt_with_k8s_context(k8s):
    # Result retrieved from --namespace command line option or default from kube context when provided
    assert options.namespace.prompt('test-namespace-from-command-line') == 'test-namespace-from-command-line'
    # Result retrieved from kube context
    assert options.namespace.prompt('test') == 'test'


def test_options_namespace_prompt_non_interactrive_without_k8s_context(mocker, k8s):
    # When context is not set, assert that value from cli-config is used
    mocker.patch('kxicli.common.is_interactive_session', utils.return_false)
    common.config.config['default']['namespace'] = 'test-namespace-from-config'
    assert options.namespace.prompt() == 'test-namespace-from-config'


def test_options_namespace_prompt_prompts_user_without_k8s_context(k8s, capsys, mocker, monkeypatch):
    # When neither context nor cli-config is set, assert user is prompted
    common.config.config['default'].pop('namespace')
    k8s.config.namespace = None
    mocker.patch('kxicli.common.is_interactive_session', utils.return_true)
    monkeypatch.setattr(SYS_STDIN, io.StringIO('test-namespace-from-prompt'))
    assert options.namespace.prompt() == 'test-namespace-from-prompt'
    assert capsys.readouterr().out == '\nPlease enter a namespace to run in: '


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


def test_options_output_file_decorator():
    assert options.output_file.decorator().func == click.option
    assert options.output_file.decorator().args == ('--output-file',)
    assert options.output_file.decorator().keywords['default']() == 'values.yaml'
    assert options.output_file.decorator().keywords['help'] == 'Name for the generated values file'


def test_options_output_file_prompt():
    # Result retrieved from --output-file command line option when provided
    assert options.output_file.prompt('a-test-output-file-name.yaml') == 'a-test-output-file-name.yaml'
    # Result retrieved from default
    assert options.output_file.prompt() == 'values.yaml'
    # Result retrieved from config when entry exists
    common.config.config['default']['install.outputFile'] = 'another-test-output-file-name.yaml'
    assert options.output_file.prompt() == 'another-test-output-file-name.yaml'


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


def test_options_filepath_prompt():
    # Result retrieved from --filepath command line option when provided
    assert options.filepath.prompt('a-new-filepath-name.yaml') == 'a-new-filepath-name.yaml'
    # Exception is raised when no tty is attached
    with pytest.raises(Exception) as e:
        options.filepath.prompt()
    assert isinstance(e.value, click.ClickException)
    assert f'Could not find expected option. Please set command line argument (\'-f\', \'--filepath\') or configuration value install.filepath in config file {common.config.config_file}' in e.value.message


@pytest.mark.parametrize("k8s_namespace", [None, "default", "current_context_namespace"])
def test_options_namespace_prompt_cli(k8s, mocker, k8s_namespace):
    """Result retrieved from --namespace command line option when provided."""
    k8s.config.namespace = k8s_namespace
    interactive_prompt = mocker.patch("kxicli.options.interactive_prompt", return_value="interactive_value")
    is_interactive_session = mocker.patch("kxicli.common.is_interactive_session", return_value=False)
    assert options.namespace.prompt("namespace-from-command-line") == 'namespace-from-command-line'
    interactive_prompt.assert_not_called()
    is_interactive_session.assert_not_called()


@pytest.mark.parametrize("k8s_namespace", [None, "default", "current_context_namespace"])
def test_options_namespace_prompt_config(k8s, mocker, k8s_namespace):
    """Result retrieved from config when entry exists. Retrieved from files/test-cli-config"""
    k8s.config.namespace = k8s_namespace
    interactive_prompt = mocker.patch("kxicli.options.interactive_prompt", return_value="interactive_value")
    is_interactive_session = mocker.patch("kxicli.common.is_interactive_session", return_value=False)
    assert options.namespace.prompt() == "test"
    interactive_prompt.assert_not_called()
    is_interactive_session.assert_not_called()
    

def test_options_namespace_prompt_no_config(k8s, mocker):
    """Result retrieved when no cli and no config is present, but valid corrent context."""
    k8s.config.namespace = "current_context_namespace"
    interactive_prompt = mocker.patch("kxicli.options.interactive_prompt", return_value="interactive_value")
    is_interactive_session = mocker.patch("kxicli.common.is_interactive_session", return_value=False)
    common.config.config['default'].pop('namespace')
    assert options.namespace.prompt() == "current_context_namespace"
    is_interactive_session.assert_not_called()
    interactive_prompt.assert_not_called()
    
    
@pytest.mark.parametrize("k8s_namespace", [None, "default"])
def test_options_namespace_prompt_exception(k8s, mocker, k8s_namespace):
    """Result retrieved when no cli and no config is present, and default namespace in current context."""
    k8s.config.namespace = k8s_namespace
    interactive_prompt = mocker.patch("kxicli.options.interactive_prompt", return_value="interactive_value")
    is_interactive_session = mocker.patch("kxicli.common.is_interactive_session", return_value=False)
    common.config.config['default'].pop('namespace')
    with pytest.raises(click.ClickException, match=rf"Could not find expected option. Please set command line argument \('-n', '--namespace'\) or configuration value namespace in config file {common.config.config_file}"):
        assert options.namespace.prompt()
    is_interactive_session.assert_called_once()
    interactive_prompt.assert_not_called()
        
        
@pytest.mark.parametrize("k8s_namespace", [None, "default"])
def test_options_namespace_prompt_no_config_tty(k8s, mocker, k8s_namespace):
    """Result retrieved from input when TTY."""
    k8s.config.namespace = k8s_namespace
    interactive_prompt = mocker.patch("kxicli.options.interactive_prompt", return_value="interactive_value")
    is_interactive_session = mocker.patch("kxicli.common.is_interactive_session", return_value=True)
    common.config.config['default'].pop('namespace')
    assert options.namespace.prompt() == "interactive_value"
    is_interactive_session.assert_called_once()
    interactive_prompt.assert_called_once()
