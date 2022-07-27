import os
import io
import yaml
import kubernetes as k8s
from kxicli import common

test_kube_config = os.path.dirname(__file__) + '/files/test-kube-config'

with open(test_kube_config, 'r') as f:    
    k8s_config = yaml.full_load(f)

def mocked_all_crds_exist(name):
    return True

def mocked_one_crd_exists(name):
    return name == 'testcrd'

def mock_k8s_contexts():
    return ['', k8s_config['contexts'][0]]

def mocked_k8s_list_empty_config():
    return ([], {'context':()})

def test_get_namespace(mocker):
    mocker.patch('kubernetes.config.list_kube_config_contexts', mock_k8s_contexts)
    
    res = common.get_namespace(None)
    assert res[1] == 'test'
    assert res[0] == k8s_config['contexts'][0]
    assert 'cluster' in res[0]['context'].keys()

def test_get_namespace_prompts_when_no_context_set(mocker,monkeypatch):
    mocker.patch('kubernetes.config.list_kube_config_contexts', mocked_k8s_list_empty_config)
    monkeypatch.setattr('sys.stdin', io.StringIO('a-test-namespace'))
    
    res = common.get_namespace(None)
    assert res[1] == 'a-test-namespace'

def test_get_existing_crds_return_all_crds(mocker):
    mocker.patch('kxicli.common.crd_exists', mocked_all_crds_exist)
    assert common.get_existing_crds(['testcrd']) == ['testcrd']
    assert common.get_existing_crds(['testcrd', 'testcrd2']) == (['testcrd', 'testcrd2'])
    assert common.get_existing_crds(['testcrd', 'testcrd2', 'testcrd3']) == (['testcrd', 'testcrd2', 'testcrd3'])

def test_get_existing_crds_return_existing_crds_only(mocker):
    mocker.patch('kxicli.common.crd_exists', mocked_one_crd_exists)
    assert common.get_existing_crds(['testcrd']) == ['testcrd']
    assert common.get_existing_crds(['testcrd', 'testcrd2']) == (['testcrd'])
    assert common.get_existing_crds(['testcrd', 'testcrd2', 'testcrd3']) == (['testcrd'])
