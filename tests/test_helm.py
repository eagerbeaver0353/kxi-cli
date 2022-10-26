import subprocess
import click
import pytest

from kxicli.resources import helm
from kxicli.commands.common import helm as common_helm

HELM_BIN_KEY = 'HELM_BIN'
HELM_BIN_VAL = 'helm'
HELM_CACHE_KEY = 'HELM_CACHE_HOME'
HELM_CACHE_VAL = '/home/test/.cache/helm'
HELM_RESPOSITORY_CACHE_KEY = 'HELM_REPOSITORY_CACHE'
HELM_RESPOSITORY_CACHE_VAL = f'{HELM_CACHE_VAL}/repository'

SAMPLE_OUTPUT = f'''{HELM_BIN_KEY}="{HELM_BIN_VAL}"
{HELM_CACHE_KEY}="{HELM_CACHE_VAL}"
{HELM_RESPOSITORY_CACHE_KEY}="{HELM_RESPOSITORY_CACHE_VAL}"'''.encode()

REPO = 'kxi-insights'
CHART = 'kxi-operator'
DEST =  HELM_RESPOSITORY_CACHE_VAL
VERSION = '1.2.3'

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
    mocker.patch('subprocess.check_output', lambda x: x)
    cmd = helm.fetch(REPO, CHART, DEST, VERSION)

    assert cmd == ['helm', 'fetch', f'{REPO}/{CHART}', '--destination', DEST, '--version', VERSION]

def test_fetch_raises_exception(mocker):
    mock = mocker.patch('subprocess.check_output')
    mock.side_effect = subprocess.CalledProcessError(1, ['helm', 'fetch'])

    with pytest.raises(Exception) as e:
        helm.fetch(REPO, CHART)

    assert isinstance(e.value, click.ClickException)
    assert isinstance(e.value.message, subprocess.CalledProcessError)

def test_helm_install_without_file_or_secret_raises_exception():
    with pytest.raises(Exception) as e:
        common_helm.helm_install('test_release', 'test_chart', None, None)

    assert isinstance(e.value, click.ClickException)
    assert e.value.message == 'Must provide one of values file or secret. Exiting install'

def test_helm_install_error_raises_exception(mocker):
    mocker.patch('subprocess.run').side_effect = subprocess.CalledProcessError(1, ['helm', 'upgrade'])
    with pytest.raises(Exception) as e:
        common_helm.helm_install('test_release', 'test_chart', 'test-values-file.yaml', None)
    assert isinstance(e.value, click.ClickException)
    assert e.value.message == "Command '['helm', 'upgrade']' returned non-zero exit status 1."
