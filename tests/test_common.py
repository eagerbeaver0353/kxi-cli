import io
import os
import pytest
import yaml
from pathlib import Path
import click
import time
from requests.exceptions import HTTPError
import requests
import json
from functools import partial

from kxicli import common
from kxicli import config
from kxicli import phrases
from utils import mock_kube_crd_api,mock_load_kube_config, mock_load_kube_config_incluster,  get_crd_body, raise_not_found, raise_conflict, return_none, IPATH_CLICK_PROMPT
import mocks
config.load_config('default')

test_kube_config = os.path.dirname(__file__) + '/files/test-kube-config'

PASSWORD = 's3cr3t'
TEST_ACCESS_TOKEN = 'abc1234'


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

def test_read_crd_returns_valid_crd(mocker):
    mock_kube_crd_api(mocker)
    assert get_crd_body('test') == common.read_crd('test')

def test_read_crd_returns_none_when_not_found(mocker):
    mock_kube_crd_api(mocker, read=raise_not_found)
    assert common.read_crd('test') is None

def test_read_crd_logs_exception(mocker, capsys):
    mock_kube_crd_api(mocker, read=raise_conflict)
    with pytest.raises(Exception) as e:
        common.read_crd('test')
    assert isinstance(e.value, click.ClickException)
    assert 'Exception when calling ApiextensionsV1Api->read_custom_resource_definition: (409)' in e.value.message

def test_crd_exists(mocker):
    mock_kube_crd_api(mocker)
    assert common.crd_exists('test')

    mock_kube_crd_api(mocker, read=return_none)
    assert not common.crd_exists('test')


glob = None
def set_glob(x):
    global glob
    glob = x

def read_glob(x):
    return glob

def delete_glob(x):
    global glob
    glob = None


def test_delete_crd(mocker):
    set_glob('test')
    mock_kube_crd_api(mocker, delete=delete_glob)
    common.delete_crd('test')
    assert glob == None


def test_delete_crd_raises_exception_on_other_delete_error(mocker):
    mock_kube_crd_api(mocker, delete=raise_conflict)
    with pytest.raises(Exception) as e:
        common.delete_crd('test')
    assert 'Exception when calling ApiextensionsV1Api->delete_custom_resource_definition' in e.value.message


def test_replace_crd_calls_create_if_not_found(mocker):
    mock_kube_crd_api(mocker, create=set_glob, read=return_none)

    common.replace_crd('test', get_crd_body('test'))
    assert glob == get_crd_body('test')

def test_replace_crd_calls_delete_and_create_if_found(mocker):
    mock = mock_kube_crd_api(mocker, create=set_glob, read=read_glob, delete=delete_glob)

    body = get_crd_body('x').to_dict()
    common.replace_crd('x', body)

    body['metadata']['resourceVersion'] = '1'
    assert glob == body
    assert mock.call_count == 2

def test_replace_crd_calls_complete_if_crd_doesnt_exist(mocker):
    mock = mock_kube_crd_api(mocker, create=set_glob, read=return_none,  delete=raise_not_found)

    body = get_crd_body('x').to_dict()
    common.replace_crd('x', body)
    assert glob == body

def test_replace_crd_raises_exception_on_other_delete_error(mocker):
    mock = mock_kube_crd_api(mocker, delete=raise_conflict)

    with pytest.raises(Exception) as e:
        common.replace_crd('test', get_crd_body('test'))
    assert mock.call_count == 1
    assert 'Exception when calling ApiextensionsV1Api->delete_custom_resource_definition' in e.value.message

def test_replace_crd_tries_again_on_crd_existing(mocker):
    # create waits 10s while waiting for delete to complete
    mock_k8s = mock_kube_crd_api(mocker)
    mock_time = mocker.patch('time.sleep')

    with pytest.raises(Exception) as e:
        common.replace_crd('test', get_crd_body('test'))
    assert mock_k8s.call_count == 11
    assert mock_time.call_count == 10
    assert 'Timed out waiting for CRD test to be deleted' in e.value.message

def test_replace_crd_raises_exception_on_create_error(mocker):
    mock = mock_kube_crd_api(mocker, create=raise_conflict, read=return_none)

    with pytest.raises(Exception) as e:
        common.replace_crd('test', get_crd_body('test'))
    assert 'Exception when calling ApiextensionsV1Api->create_custom_resource_definition' in e.value.message


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


def test_load_kube_config(mocker, capsys):
    mocker.patch('kxicli.common.CONFIG_ALREADY_LOADED', False)  
    mock_load_kube_config_incluster(mocker)
    mocker.patch('kubernetes.config.load_kube_config')
    res = common.load_kube_config()     
    assert res is None
    
def test_load_kube_config_second_run(mocker, capsys):
    mocker.patch('kxicli.common.CONFIG_ALREADY_LOADED', True)      
    mock_load_kube_config_incluster(mocker)
    mocker.patch('kubernetes.config.load_kube_config')    
    res = common.load_kube_config() 
    assert res is None
    
def test_load_kube_config_no_config(mocker, capsys):    
    mock_load_kube_config(mocker)
    mock_load_kube_config_incluster(mocker)
    mocker.patch('kxicli.common.CONFIG_ALREADY_LOADED', False)    
    with pytest.raises(Exception) as e:
        common.load_kube_config()         
    assert isinstance(e.value, click.ClickException)
    assert "Kubernetes cluster config not found" in e.value.message   
           
def test_load_incluster_pass_load_fails(mocker, capsys):    
    mocker.patch('kxicli.common.CONFIG_ALREADY_LOADED', False)
    mocker.patch('kubernetes.config.load_incluster_config')
    mock_load_kube_config(mocker)
    res = common.load_kube_config()         
    assert res is None  

def test_get_access_token_raises_exception(mocker):
    mocker.patch('requests.post', partial(
        mocks.http_response, 
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))
    with pytest.raises(Exception) as e:
        common.get_access_token(hostname='test.kx.com', client_id='1234', client_secret='super-secret', realm='test')
    assert isinstance(e.value, click.ClickException)
    assert e.value.message == 'Failed to request access token:  404 None (<Response [404]>)'

def test_get_admin_token_raises_exception(mocker):
    mocker.patch('requests.post', partial(
        mocks.http_response, 
        status_code=404,
        content=json.dumps({'message': "Unknown", 'detail': {'message': "HTTP Error"}}).encode('utf-8')
    ))
    with pytest.raises(Exception) as e:
        common.get_admin_token(hostname='test.kx.com', username='username', password='password')
    assert isinstance(e.value, click.ClickException)
    assert e.value.message == 'Failed to request admin access token:  404 None (<Response [404]>)'

def test_get_admin_token_returns_access_token(mocker):
    mocker.patch('requests.post', partial(
        mocks.http_response, 
        status_code=200,
        content=json.dumps({'access_token':TEST_ACCESS_TOKEN}).encode('utf-8')
    ))
    r = common.get_admin_token(hostname='test.kx.com', username='username', password='password')
    assert isinstance(r, str)
    assert r == TEST_ACCESS_TOKEN

def mocked_json_response(**kwargs):
    sample = {
        'error': 'sampl_error'
    }
    return sample
def test_parse_http_exception(mocker):
    #mocker.patch('e.response', mocked_json_response)
    e = HTTPError()
    e.response = requests.Response()
    e.response.status_code = 200
    e.response._content=json.dumps({ 'errorMessage':'ErrorMessageError'}).encode('utf-8')
    res, msg = common.parse_http_exception(e)
    assert msg == "ErrorMessageError"

    e = HTTPError()
    e.response = requests.Response()
    e.response.status_code = 200
    e.response._content=json.dumps({ 'error':'ErrorError'}).encode('utf-8')
    res, msg = common.parse_http_exception(e)
    assert msg == "ErrorError"
