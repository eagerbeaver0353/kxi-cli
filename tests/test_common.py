import io
import os
from unittest.mock import MagicMock
import pyk8s
import pytest
import yaml
from pathlib import Path
import click
import time
from requests.exceptions import HTTPError
import requests
import json

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

def test_read_crd_returns_valid_crd(k8s):
    mock_kube_crd_api(k8s)
    assert get_crd_body('test') == common.read_crd('test')

def test_read_crd_returns_none_when_not_found(k8s):
    mock_kube_crd_api(k8s, read=return_none)
    assert common.read_crd('test') is None

def test_read_crd_logs_exception(k8s, capsys):
    mock_kube_crd_api(k8s, read=raise_conflict)
    with pytest.raises(Exception, match=r"Exception when while trying to find CustomResourceDefinition\(test\)") as e:
        common.read_crd('test')
    assert isinstance(e.value, click.ClickException)

def test_crd_exists(k8s):
    mock_kube_crd_api(k8s)
    assert common.crd_exists('test')

    mock_kube_crd_api(k8s, read=return_none)
    assert not common.crd_exists('test')


def test_delete_crd(k8s):
    mock = mock_kube_crd_api(k8s)
    common.delete_crd('test')
    mock.delete.assert_called_once()


def test_delete_crd_raises_exception_on_other_delete_error(k8s):
    mock_kube_crd_api(k8s, delete=raise_conflict)
    with pytest.raises(Exception, match=r'Exception when trying to delete CustomResourceDefinition\(test\)'):
        common.delete_crd('test')


def test_replace_crd_calls_create_if_not_found(k8s, mocker):
    mock = mock_kube_crd_api(k8s, read=return_none)

    common.replace_crd('test', get_crd_body('test'))
    
    mock.delete.assert_not_called()
    mock.create.assert_called_once_with(get_crd_body('test'))
    

def test_replace_crd_calls_delete_and_create_if_found(k8s, mocker):
    mock = mock_kube_crd_api(k8s)
    mocker.patch.object(pyk8s.models.V1CustomResourceDefinition, "wait_until_not_ready")

    body = get_crd_body('x').to_dict()
    common.replace_crd('x', body)
    
    mock.delete.assert_called_once()
    assert mock.delete.call_args.kwargs["name"] == "x"
    mock.create.assert_called_once_with(body)
    

def test_replace_crd_calls_complete_if_crd_doesnt_exist(k8s, mocker):
    mock = mock_kube_crd_api(k8s, read=return_none, delete=raise_not_found)
    mocker.patch.object(pyk8s.models.V1CustomResourceDefinition, "wait_until_not_ready")

    body = get_crd_body('x').to_dict()
    common.replace_crd('x', body)
    
    mock.delete.assert_not_called()
    mock.create.assert_called_once_with(body)

def test_replace_crd_raises_exception_on_other_delete_error(k8s):
    mock = mock_kube_crd_api(k8s, delete=raise_conflict)

    with pytest.raises(Exception, match=r'Exception when trying to delete CustomResourceDefinition\(test\)'):
        common.replace_crd('test', get_crd_body('test'))

def test_replace_crd_tries_again_on_crd_existing(k8s, mocker):
    # create waits 10s while waiting for delete to complete
    mock_k8s = mock_kube_crd_api(k8s)
    mocker.patch.object(pyk8s.models.V1CustomResourceDefinition, "wait_until_not_ready", 
                        side_effect=pyk8s.exceptions.EventTimeoutError(last=None))

    with pytest.raises(Exception, match='Timed out waiting for CRD test to be deleted'):
        common.replace_crd('test', get_crd_body('test'))

def test_replace_crd_raises_exception_on_create_error(k8s, mocker):
    mock = mock_kube_crd_api(k8s, create=raise_conflict, read=return_none)
    mocker.patch.object(pyk8s.models.V1CustomResourceDefinition, "wait_until_not_ready")

    with pytest.raises(Exception, match=r'Exception when trying to create CustomResourceDefinition\(test\)'):
        common.replace_crd('test', get_crd_body('test'))


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

def mocked_json_response(**kwargs):
    sample = {
        'error': 'sampl_error'
    }
    return sample

def test_parse_http_exception_message(mocker):
    e = HTTPError()
    e.response = requests.Response()
    e.response.status_code = 200
    e.response._content=json.dumps({ 'errorMessage':'ErrorMessageError'}).encode('utf-8')
    res, msg = common.parse_http_exception(e)
    assert msg == "ErrorMessageError"


def test_parse_http_exception(mocker):
    e = HTTPError()
    e.response = requests.Response()
    e.response.status_code = 200
    e.response._content=json.dumps({ 'error':'ErrorError'}).encode('utf-8')
    res, msg = common.parse_http_exception(e)
    assert msg == "ErrorError"
    

def test_handle_http_exception(mocker):
    e = HTTPError()
    e.response = requests.Response()
    e.response.status_code = 200
    e.response._content=json.dumps({ 'error':'ErrorError'}).encode('utf-8')
    with pytest.raises(click.ClickException, match=r"prefix 200 None \(ErrorError\)"):
        common.handle_http_exception(e, "prefix")


def test_handle_http_exception_no_response(mocker):
    e = HTTPError("No Response Error")
    delattr(e, "response")
    with pytest.raises(click.ClickException, match="No Response Error"):
        common.handle_http_exception(e, "prefix")
