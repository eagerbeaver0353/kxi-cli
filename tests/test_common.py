import io
import os
import pytest
import yaml
from pathlib import Path
import click

from kxicli import common
from kxicli import config
from kxicli import phrases
from utils import mock_kube_crd_api, get_crd_body, raise_not_found, raise_conflict, return_none, IPATH_CLICK_PROMPT

config.load_config('default')

test_kube_config = os.path.dirname(__file__) + '/files/test-kube-config'

PASSWORD = 's3cr3t'

PASSWORD_LIST = [
    'test',
    'Test',
    PASSWORD,
    PASSWORD
]

with open(test_kube_config, 'r') as f:
    k8s_config = yaml.full_load(f)


def mocked_all_crds_exist(name):
    return True


def mocked_one_crd_exists(name):
    return name == 'testcrd'


def mock_k8s_contexts():
    return ['', k8s_config['contexts'][0]]


def mocked_k8s_list_empty_config():
    return ([], {'context': ()})


def test_get_namespace(mocker):
    mocker.patch('kubernetes.config.list_kube_config_contexts', mock_k8s_contexts)

    res = common.get_namespace(None)
    assert res[1] == 'test'
    assert res[0] == k8s_config['contexts'][0]
    assert 'cluster' in res[0]['context'].keys()


def test_get_namespace_prompts_when_no_context_set(mocker, monkeypatch):
    mocker.patch('kubernetes.config.list_kube_config_contexts', mocked_k8s_list_empty_config)
    monkeypatch.setattr('sys.stdin', io.StringIO('a-test-namespace'))

    res = common.get_namespace(None)
    assert res[1] == 'a-test-namespace'


def test_get_existing_crds_return_all_crds(mocker):
    mocker.patch('kxicli.common.crd_exists', mocked_all_crds_exist)
    #mock_kube_crd_api(mocker)
    assert common.get_existing_crds(['testcrd']) == ['testcrd']
    assert common.get_existing_crds(['testcrd', 'testcrd2']) == (['testcrd', 'testcrd2'])
    assert common.get_existing_crds(['testcrd', 'testcrd2', 'testcrd3']) == (['testcrd', 'testcrd2', 'testcrd3'])


def test_get_existing_crds_return_existing_crds_only(mocker):
    mocker.patch('kxicli.common.crd_exists', mocked_one_crd_exists)
    assert common.get_existing_crds(['testcrd']) == ['testcrd']
    assert common.get_existing_crds(['testcrd', 'testcrd2']) == (['testcrd'])
    assert common.get_existing_crds(['testcrd', 'testcrd2', 'testcrd3']) == (['testcrd'])

def test_read_crd_returns_valid_crd(mocker):
    mock_kube_crd_api(mocker)
    assert get_crd_body('test') == common.read_crd('test')

def test_read_crd_returns_none_when_not_found(mocker):
    mock_kube_crd_api(mocker, read=raise_not_found)
    assert common.read_crd('test') is None

def test_read_crd_logs_exception(mocker, capsys):
    mock_kube_crd_api(mocker, read=raise_conflict)
    common.read_crd('test')

    captured = capsys.readouterr()
    assert 'Exception when calling ApiextensionsV1Api->read_custom_resource_definition: (409)' in captured.out

def test_crd_exists(mocker):
    mock_kube_crd_api(mocker)
    assert common.crd_exists('test')

    mock_kube_crd_api(mocker, read=return_none)
    assert not common.crd_exists('test')


glob = None
glob_y = None
def set_glob(x):
    global glob
    glob = x

def set_glob2(x, y):
    global glob_y
    glob_y = y

def test_replace_crd_calls_create_if_not_found(mocker):
    mock_kube_crd_api(mocker, create=set_glob, read=return_none)

    common.replace_crd('test', get_crd_body('test'))
    assert glob == get_crd_body('test')

def test_replace_crd_calls_replace_if_found(mocker):
    mock_kube_crd_api(mocker, replace=set_glob2)

    body = get_crd_body('x').to_dict()
    common.replace_crd('x', body)

    body['metadata']['resourceVersion'] = '1'
    assert glob_y == body

def test_replace_crd_tries_again_on_conflict(mocker):
    mock = mocker.patch('kxicli.common.create_or_replace_crd', side_effect=raise_conflict)
    with pytest.raises(Exception):
        common.replace_crd('test', get_crd_body('test'))
    assert mock.call_count == 2

def test_replace_crd_only_runs_once_on_other_k8s_error(mocker):
    mock = mocker.patch('kxicli.common.create_or_replace_crd', side_effect=raise_not_found)
    common.replace_crd('test', get_crd_body('test'))
    assert mock.call_count == 1


def test_extract_files_from_tar_throws_file_not_found():
    path = Path(__file__).parent / 'files' / 'helm' / 'kxi-operator-1.2.3.tgz'
    files = ['not_there']
    with pytest.raises(Exception) as e:
        common.extract_files_from_tar(path, files)

    assert isinstance(e.value, click.ClickException)
    assert e.value.message == f'File not_there not found in {path}'

def test_extract_files_from_tar_throws_tar_does_not_exist():
    path = Path(__file__).parent / 'files' / 'helm' / 'abc.tgz'
    with pytest.raises(Exception) as e:
        common.extract_files_from_tar(path, [])

    assert isinstance(e.value, click.ClickException)
    assert e.value.message == f'{path} does not exist or is not a valid tar archive'


def test_extract_files_from_tar_when_file_too_big():
    path = Path(__file__).parent / 'files' / 'helm' / 'kxi-operator-1.2.3.tgz'
    file = ['kxi-operator/crds/insights.kx.com_assemblies.yaml']
    max_size = 100

    with pytest.raises(Exception) as e:
        common.extract_files_from_tar(path, file, max_size)
    assert isinstance(e.value, click.ClickException)
    assert e.value.message == f'Refused to load more than {max_size} bytes from {file[0]}'

def test_enter_password_when_they_match(mocker):
    mock = mocker.patch(IPATH_CLICK_PROMPT, return_value=PASSWORD)

    # click.prompt should only be called twice when it's valid
    assert PASSWORD == common.enter_password('Enter password')
    assert mock.call_count == 2

def test_enter_password_prompts_again_if_they_dont_match(mocker, capsys):
    def get_password(*args, **kwargs):
        return PASSWORD_LIST.pop(0)

    mocker.patch(IPATH_CLICK_PROMPT, get_password)
    res = common.enter_password('Enter password')
    captured = capsys.readouterr()

    # the captured output should show that the passwords didn't match
    assert PASSWORD == res
    assert phrases.password_no_match in captured.out
