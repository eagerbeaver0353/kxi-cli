import json
import subprocess
from typing import List
import click
import pyk8s
import pytest

from functools import partial
from pathlib import Path
from pytest_mock import MockerFixture
from subprocess import CompletedProcess, CalledProcessError
from kxicli.commands import install

from kxicli.resources import helm
import const
import utils

HELM_BIN_KEY = 'HELM_BIN'
HELM_BIN_VAL = 'helm'
HELM_CACHE_KEY = 'HELM_CACHE_HOME'
HELM_CACHE_VAL = '/home/test/.cache/helm'
HELM_RESPOSITORY_CACHE_KEY = 'HELM_REPOSITORY_CACHE'
HELM_RESPOSITORY_CACHE_VAL = f'{HELM_CACHE_VAL}/repository'

SAMPLE_OUTPUT = f'''{HELM_BIN_KEY}="{HELM_BIN_VAL}"
{HELM_CACHE_KEY}="{HELM_CACHE_VAL}"
{HELM_RESPOSITORY_CACHE_KEY}="{HELM_RESPOSITORY_CACHE_VAL}"'''.encode()

RELEASE='test-chart-name'
REPO = 'kxi-insights'
CHART = 'kxi-operator'
DEST =  HELM_RESPOSITORY_CACHE_VAL
VERSION = '1.2.3'
NAMESPACE = 'test-namespace'

fun_subprocess_check_out: str = 'subprocess.check_output'
fun_subprocess_run: str = 'subprocess.run'
config_json_file_name: str = 'config.json'

# Mocks

def subprocess_check_out_helm_version_valid(*popenargs, timeout=None, **kwargs) -> str:
    return f'v{helm.minimum_helm_version}'


def subprocess_check_out_helm_version_invalid(*popenargs, timeout=None, **kwargs) -> str:
    return 'v3.7.0'


def subprocess_check_out_helm_version_exception(*popenargs, timeout=None, **kwargs) -> str:
    raise CalledProcessError(returncode=1, cmd=popenargs[0])


def subprocess_run_helm_fail(
        *popenargs,
        input=None, capture_output=False, timeout=None, check=False, **kwargs
):
    raise CalledProcessError(returncode=1, cmd=popenargs[0])


def subprocess_run_helm_success_install_with_res(
        *popenargs, res: dict,
        input=None, capture_output=False, timeout=None, check=False, **kwargs
):
    env: dict = kwargs['env']
    res['env'] = env
    res['cmd'] = popenargs[0]
    res['DOCKER_CONFIG'] = env['DOCKER_CONFIG']
    with open(str(Path(env['DOCKER_CONFIG']) / config_json_file_name)) as dc:
        res['dockerconfigjson'] = dc.read()
    return CompletedProcess(args=popenargs[0], returncode=0, stdout='', stderr='')


def subprocess_run_helm_success_uninstall_with_res(
        *popenargs, res: dict,
        input=None, capture_output=False, timeout=None, check=False, **kwargs
):
    res['cmd'] = popenargs[0]
    return CompletedProcess(args=popenargs[0], returncode=0, stdout='', stderr='')


def compare_completed_process(cp1: CompletedProcess, cp2: CompletedProcess) -> bool:
    return cp1.args == cp2.args and \
           cp1.returncode == cp2.returncode and \
           cp1.stdout == cp2.stdout and \
           cp1.stderr == cp2.stderr


# Tests

def test_helm_env_correctly_splits_output(mocker):
    mocker.patch('subprocess.check_output',return_value=SAMPLE_OUTPUT)
    assert helm.env() == {
        HELM_BIN_KEY: HELM_BIN_VAL,
        HELM_CACHE_KEY: HELM_CACHE_VAL,
        HELM_RESPOSITORY_CACHE_KEY: HELM_RESPOSITORY_CACHE_VAL
    }

def test_helm_env_raises_exception(mocker):
    mock = mocker.patch('subprocess.check_output')
    mock.side_effect = subprocess.CalledProcessError(1, ['helm', 'env'])

    with pytest.raises(Exception) as e:
        helm.env()

    assert isinstance(e.value, click.ClickException)
    assert isinstance(e.value.message, subprocess.CalledProcessError)


def test_get_repository_cache_raises_exception(mocker):
    mocker.patch('subprocess.check_output',return_value='x="y"'.encode())
    with pytest.raises(Exception) as e:
        helm.get_repository_cache()

    assert isinstance(e.value, click.ClickException)
    assert e.value.message == 'Could not find HELM_REPOSITORY_CACHE in "helm env" output'


def test_get_repository_cache_returns_cache(mocker):
    mocker.patch('subprocess.check_output', return_value=SAMPLE_OUTPUT)
    assert HELM_RESPOSITORY_CACHE_VAL == helm.get_repository_cache()


def test_fetch_adds_dest_and_version(mocker):
    mocker.patch('subprocess.check_output', lambda x, env: x)
    cmd = helm.fetch(REPO, CHART, DEST, VERSION)

    assert cmd == ['helm', 'fetch', f'{REPO}/{CHART}', '--destination', DEST, '--version', VERSION]

def test_fetch_raises_exception(mocker):
    mock = mocker.patch('subprocess.check_output')
    mock.side_effect = subprocess.CalledProcessError(1, ['helm', 'fetch'])

    with pytest.raises(Exception) as e:
        helm.fetch(REPO, CHART)

    assert isinstance(e.value, click.ClickException)
    assert isinstance(e.value.message, subprocess.CalledProcessError)

def test_helm_upgrade_install_error_raises_exception(mocker):
    mocker.patch('subprocess.run').side_effect = subprocess.CalledProcessError(1, ['helm', 'upgrade'], stderr=b'Deployment failed')
    with pytest.raises(Exception) as e:
        helm.upgrade_install('test_release', 'test_chart', values_file='test-values-file.yaml')
    assert isinstance(e.value, click.ClickException)
    assert e.value.message == 'Command "helm upgrade" failed with output:\n  Deployment failed'


def test_helm_version_valid(mocker: MockerFixture):
    mocker.patch(fun_subprocess_check_out, subprocess_check_out_helm_version_valid)
    assert helm._get_helm_version() >= helm.LocalHelmVersion(version=helm.minimum_helm_version)


def test_helm_version_invalid(mocker: MockerFixture):
    mocker.patch(fun_subprocess_check_out, subprocess_check_out_helm_version_invalid)
    assert helm._get_helm_version() < helm.LocalHelmVersion(version=helm.minimum_helm_version)


def test_helm_version_exception(mocker: MockerFixture):
    mocker.patch(fun_subprocess_check_out, subprocess_check_out_helm_version_exception)
    with pytest.raises(click.ClickException):
        assert helm._get_helm_version()


def test_helm_install_success(mocker: MockerFixture):
    res: dict = {}
    expected_cmd: List[str] = [
        'helm', 'upgrade', '--install', '--version', VERSION, RELEASE, CHART,
        '--namespace', NAMESPACE
    ]

    subprocess_run_helm_success_helm_install = partial(subprocess_run_helm_success_install_with_res, res=res)

    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install)
    mocker.patch.object(pyk8s.models.V1Namespace, "ensure", utils.return_none)

    actual_res = helm.upgrade_install(
        release=RELEASE,
        chart=CHART,
        version=VERSION,
        namespace=NAMESPACE,
        docker_config=utils.fake_docker_config_yaml
    )

    assert 'DOCKER_CONFIG' in dict(res['env'])
    assert res['dockerconfigjson'] == utils.fake_docker_config_yaml
    assert res['cmd'] == expected_cmd
    assert compare_completed_process(
        actual_res,
        CompletedProcess(args=expected_cmd, returncode=0, stdout='', stderr='')
    )


def test_helm_install_fail(mocker: MockerFixture):
    mocker.patch(fun_subprocess_run, subprocess_run_helm_fail)
    mocker.patch.object(pyk8s.models.V1Namespace, "ensure", utils.return_none)
    with pytest.raises(click.ClickException):
        helm.upgrade_install(
            release=RELEASE,
            chart=CHART,
            version=VERSION,
            namespace=NAMESPACE,
            docker_config=utils.fake_docker_config_yaml
        )


def test_helm_uninstall_success(mocker: MockerFixture):
    res: dict = {}
    expected_cmd: List[str] = [
        'helm', 'uninstall', RELEASE, '--namespace', NAMESPACE
    ]
    expected_res: CompletedProcess = CompletedProcess(args=expected_cmd, returncode=0, stdout='', stderr='')

    subprocess_run_helm_success_uninstall = partial(subprocess_run_helm_success_uninstall_with_res, res=res)

    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_uninstall)
    mocker.patch.object(pyk8s.models.V1Namespace, "ensure", utils.return_none)
    actual_res = helm.uninstall(
        release=RELEASE,
        namespace=NAMESPACE
    )
    assert compare_completed_process(actual_res, expected_res)
    assert res['cmd'] == expected_cmd


def test_helm_uninstall_fail(mocker: MockerFixture):
    mocker.patch(fun_subprocess_run, subprocess_run_helm_fail)
    mocker.patch.object(pyk8s.models.V1Namespace, "ensure", utils.return_none)
    with pytest.raises(click.ClickException):
        helm.uninstall(
            release=RELEASE,
            namespace=NAMESPACE
        )


def test_get_helm_version_checked(mocker: MockerFixture):
    mocker.patch(fun_subprocess_check_out, subprocess_check_out_helm_version_valid)
    assert type(helm.get_helm_version_checked()) is helm.HelmVersionChecked


def test_get_helm_version_checked_fail():
    with pytest.raises(click.ClickException):
        helm.HelmVersionChecked(
            req_helm_version=helm.required_helm_version,
            local_helm_version=helm.LocalHelmVersion(subprocess_check_out_helm_version_invalid([]))
        )
def mocked_helm_history(base_command, stdout=subprocess.PIPE, check=True, capture_output=True, text=True):
    return subprocess.CompletedProcess(
        args=base_command,
        returncode=0,
        stdout=b'[{"revision": 1, "status": "deployed"}, {"revision": 2, "status": "uninstalled"}]'
    )

def mocked_helm_history_json(base_command, check=True, capture_output=True, text=True):
    return subprocess.CompletedProcess(
        args=base_command,
        returncode=0,
        stdout='[{"revision": 1, "status": "deployed"}, {"revision": 2, "status": "uninstalled"}]'
    )


def test_history_success_json(mocker):
    mocker.patch('subprocess.run', mocked_helm_history_json)
    release = "myrelease"
    output = [{"revision": 1, "status": "deployed"}, {"revision": 2, "status": "uninstalled"}]
    assert helm.history(release, 'json', None, None, 'kxi-operator') == (output, output)

def test_history_success(mocker):
    mocker.patch('subprocess.run', mocked_helm_history)
    release = "myrelease"
    res = helm.history(release, None, None, None, 'kxi-operator')
    assert res is None

def test_history_fail(mocker):
    error_msg = "command not found: helm"
    mocker.patch('subprocess.run').side_effect = subprocess.CalledProcessError(1, "helm", error_msg)
    release = "myrelease"
    output = []
    assert helm.history(release, False, None, None, 'kxi-operator') == output

def test_history_fail_json(mocker):
    error_msg = "command not found: helm"
    mocker.patch('subprocess.run').side_effect = subprocess.CalledProcessError(1, "helm", error_msg)
    release = "myrelease"
    output = []
    assert helm.history(release, False, None, None, 'kxi-operator') == output

def test_repo_exists(mocker):
    utils.mock_helm_repo_list(mocker, const.test_chart_repo_name, const.test_chart_repo_url)
    assert helm.repo_exists(const.test_chart_repo_name) is None
    with pytest.raises(Exception) as e:
        helm.repo_exists('a-different-repo')
    assert isinstance(e.value, helm.RepoNotFoundException)
    assert 'a-different-repo' in e.value.args[0]


def test_repo_exists_returns_error_when_repo_does_not_exist(mocker):
    mocker.patch('subprocess.run').side_effect = subprocess.CalledProcessError(1, ['helm', 'repo', 'list'])
    with pytest.raises(Exception) as e:
        helm.repo_exists(const.test_chart_repo_name)
    assert isinstance(e.value, helm.RepoNotFoundException)
    assert const.test_chart_repo_name in e.value.args[0]


def test_helm_repo_list_when_repo_exists(mocker):
    data = [{'name': const.test_chart_repo_name, 'url': const.test_chart_repo_url}]
    mocker.patch('subprocess.run').return_value = subprocess.CompletedProcess(
            args=['helm','repo','list'],
            returncode=0,
            stdout=json.dumps(data)
    )
    assert helm.repo_list() == data


def test_helm_repo_list_returns_empty_list_when_repo_search_errors(mocker):
    mocker.patch('subprocess.run').side_effect = subprocess.CalledProcessError(1, ['helm', 'repo', 'list'])
    assert helm.repo_list() == []

