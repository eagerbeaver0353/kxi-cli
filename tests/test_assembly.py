from unittest.mock import MagicMock, call
import click
import json
import os
import pyk8s
import requests
import requests_mock
import shutil
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp

import pytest
import yaml
from click.testing import CliRunner

from kxicli import common
from kxicli import main
from kxicli.commands import assembly
import mocks
import utils
from test_assembly_kxicontroller import build_assembly_object_kxic
from functools import partial

ASM_NAME = 'test_asm'
ASM_NAME2 = 'test_asm2'
ASM_NAME3 = 'test_asm3'
TEST_CLI = CliRunner()
CUSTOM_OBJECT_API = 'kubernetes.client.CustomObjectsApi'
PREFERRED_VERSION_FUNC = 'kxicli.commands.assembly.get_preferred_api_version'
PREFERRED_VERSION = 'v1'
TEST_NS = 'test_ns'
test_asm_file = os.path.dirname(__file__) + '/files/assembly-v1.yaml'
with open(test_asm_file) as f:
    test_asm = yaml.safe_load(f)

common.config.config_file = os.path.dirname(__file__) + '/files/test-cli-config'
common.config.load_config("default")


@contextmanager
def temp_asm_file(prefix: str = 'kxicli-assembly-', file_name='test_assembly_list.yaml'):
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

def build_assembly_object(name, response=False):
    """
    Create an assembly object
    Optionally add the status & last-applied-configuration annotation
    """

    object = {
        'apiVersion': 'insights.kx.com/v1',
        'kind': "Assembly",
        'metadata': {
            'name': name,
            'namespace': TEST_NS,
        }
    }

    if response:
        object['metadata']['annotations'] = {
            assembly.CONFIG_ANNOTATION: json.dumps(object)
        }
        object['status'] = {
            'conditions': [
                {
                    'status': 'True',
                    'type': 'AssemblyReady'
                }
            ]
        }

    return object


ASSEMBLY_LIST = [build_assembly_object(ASM_NAME, True), build_assembly_object(ASM_NAME2, True), build_assembly_object(ASM_NAME3)]
ASSEMBLY_BACKUP_LIST = {'items': [build_assembly_object(ASM_NAME), build_assembly_object(ASM_NAME2)]}

TRUE_STATUS = {
    'AssemblyReady': {
        'status': 'True'
    }
}

FALSE_STATUS = {
    'AssemblyReady': {
        'status': 'False'
    }
}


def raise_not_found(*_, **kwargs):
    """Helper function to test try/except blocks"""
    raise pyk8s.exceptions.NotFoundError(MagicMock())


def mocked_return_false(name):
    return False


def store_args(**args):
    global stored_args
    stored_args = args


def mock_return_conflict_for_assembly(body, *args, **kwargs):
    if body['metadata']['name'] == ASM_NAME:
        mock_return_conflict_kube(status_code=409, error_message='deploy failed',
                                  detail_message='assemblies.insights.kx.com sdk-sample-assembly already exists')
    else:
        return body
        
def mock_return_conflict_for_assembly_k8s(body, *args, **kwargs):
    if body['metadata']['name'] == ASM_NAME:
        mock_return_conflict_kube(status_code=409, error_message='deploy failed',
                             detail_message='assemblies.insights.kx.com sdk-sample-assembly already exists')
    else:
        return body

def mock_return_conflict(*args, status_code, error_message, detail_message, **kwargs):
    response = requests.Response()
    response.status_code = status_code
    error_response = {'message': error_message, 'detail': {'message': detail_message}}
    response._content = json.dumps(error_response).encode('utf-8')
    raise requests.exceptions.HTTPError(response=response)

def mock_return_conflict_kube(*args, status_code, error_message, detail_message, **kwargs):
    error_response = {'reason': error_message, 'message': detail_message}
    exception = pyk8s.exceptions.ConflictError(MagicMock())
    exception.body = json.dumps(error_response)
    raise exception

# mock the response from the Kubernetes list function
def mock_list_assemblies(k8s, response=ASSEMBLY_LIST):
    k8s.assemblies.get.return_value = response


# mock the Kubernetes create function to capture arguments
def mock_create_assemblies(k8s):
    k8s.assemblies.create.side_effect = lambda body, **kwargs: body



def mocked_k8s_list_empty_config():
    return ([], {'context': ()})


def test_format_assembly_status_if_no_status_key():
    assert assembly._format_assembly_status({}) == {}


def test_format_assembly_status_if_no_conditions_key():
    assert assembly._format_assembly_status({'status': {}}) == {}


def test_format_assembly_status_without_message_and_reason():
    formatted_status = {
        'AssemblyReady': {
            'status': 'True'
        }
    }
    assert assembly._format_assembly_status(build_assembly_object(ASM_NAME, True)) == formatted_status


def test_format_assembly_status_with_message_and_reason():
    asm = build_assembly_object(ASM_NAME, True)
    asm['status']['conditions'][0]['status'] = 'False'
    asm['status']['conditions'][0]['message'] = 'type'
    asm['status']['conditions'][0]['reason'] = 'StorageManager not ready'

    formatted_status = {
        'AssemblyReady': {
            'status': asm['status']['conditions'][0]['status'],
            'message': asm['status']['conditions'][0]['message'],
            'reason': asm['status']['conditions'][0]['reason']
        }
    }
    assert assembly._format_assembly_status(asm) == formatted_status


def test_status_with_true_status(mocker):
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.get(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}', text=json.dumps(build_assembly_object_kxic(ASM_NAME)))
        assert assembly._assembly_status(hostname='https://test.kx.com',
            client_id='client',
            client_secret='secret',
            realm='insights',
            name=ASM_NAME,
            use_kubeconfig=False,
        )


def test_status_with_true_status_k8s_api(mocker, k8s):
    k8s.assemblies.read.return_value = build_assembly_object(ASM_NAME, True)
    assert assembly._assembly_status(namespace='test_ns', name='test_asm', use_kubeconfig=True)


def test_status_with_false_status(mocker):
    # set False status in assembly
    asm = build_assembly_object_kxic(ASM_NAME, ready=False)

    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.get(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}', text=json.dumps(asm))
        assert assembly._assembly_status(hostname='https://test.kx.com',
            client_id='client',
            client_secret='secret',
            realm='insights',
            name=ASM_NAME,
            use_kubeconfig=False,
        ) == False


def test_status_with_false_status_k8s_api(mocker, k8s):
    # set False status
    asm = build_assembly_object(ASM_NAME, True)
    asm['status']['conditions'][0]['status'] = 'False'

    # mock the Kubernetes function to return asm above
    k8s.assemblies.read.return_value = asm

    assert assembly._assembly_status(namespace='test_ns', name='test_asm', use_kubeconfig=True, print_status=True) == False


def test_status_error_k8s_api(mocker, k8s):
    # mock the Kubernetes function to raise exception
    k8s.assemblies.read.side_effect = Exception("test message")

    with pytest.raises(click.ClickException, 
                       match="Exception when calling CustomObjectsApi->get_namespaced_custom_object: test message"):
        assembly._assembly_status(namespace='test_ns', name='test_asm', use_kubeconfig=True, print_status=True)


def test_get_assemblies_list_k8s_api(mocker, k8s):
    mock_list_assemblies(k8s)
    assert assembly.get_assemblies_list(namespace='test_ns') == ASSEMBLY_LIST


def test_get_assemblies_list_uses_label_selector(k8s):
    mocks.mock_assembly_list(k8s, ASSEMBLY_LIST)
    res = assembly.get_assemblies_list(namespace='test_ns')

    assert k8s.assemblies.get.call_args_list[0][1]['label_selector'] == assembly.ASM_LABEL_SELECTOR
    assert res == ASSEMBLY_LIST



def test_list_cluster_assemblies_k8s_api(k8s):
    mock = mocks.mock_assembly_list(k8s, response=ASSEMBLY_LIST)
    fs = 'metadata.namespace!=other_ns'
    res = assembly.list_cluster_assemblies(field_selector=fs)
    assert mock.get.call_args_list[0][1]['field_selector'] == fs
    assert res == ASSEMBLY_LIST


def test_backup_assemblies(k8s):
    mock_list_assemblies(k8s)
    with temp_asm_file() as test_asm_list_file:
        assert test_asm_list_file == assembly.backup_assemblies(namespace='test_ns', filepath=test_asm_list_file,
                                                                 force=False)
        with open(test_asm_list_file, 'rb') as f:
            expect = yaml.full_load(f)
            assert expect == ASSEMBLY_BACKUP_LIST


def test_backup_assemblies_when_no_assemblies_running(k8s):
    mocks.mock_assembly_list(k8s, response=[])
    with temp_asm_file() as test_asm_list_file:
        assert assembly.backup_assemblies(namespace='test_ns', filepath=test_asm_list_file, force=False) == None
        assert not os.path.exists(test_asm_list_file)


def test_add_last_applied_configuration_annotation():
    test_assembly = build_assembly_object(ASM_NAME)
    res = assembly._add_last_applied_configuration_annotation(test_assembly)
    assert assembly.CONFIG_ANNOTATION in res['metadata']['annotations']
    test_assembly['metadata']['annotations'] = {}
    assert res['metadata']['annotations'][assembly.CONFIG_ANNOTATION] == '\n' + json.dumps(test_assembly)


def test_create_assembly_submits_to_kxic_api(mocker):
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.post('https://test.kx.com/kxicontroller/assembly/cli/deploy')
        assert assembly._create_assembly('https://test.kx.com', 'client', 'secret', 'insights', \
                                  namespace='test_ns', body=test_asm, use_kubeconfig=False)
        assert m.last_request.json() == assembly._add_last_applied_configuration_annotation(test_asm)


def test_create_assembly_submits_to_k8s_api(k8s):
    mock_create_assemblies(k8s)
    assert assembly._create_assembly(None, None, None, None, namespace='test_ns', body=test_asm, use_kubeconfig=True)
    k8s.assemblies.create.assert_called_once_with(
        body=pyk8s.ResourceItem.parse_obj(assembly._add_last_applied_configuration_annotation(test_asm)), 
        namespace='test_ns')


def test_create_assemblies_from_file_creates_one_assembly(mocker):
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.post('https://test.kx.com/kxicontroller/assembly/cli/deploy')

        assert assembly.create_assemblies_from_file(hostname='https://test.kx.com', client_id='client', client_secret='secret', \
                                                realm='insights', namespace=None, filepath=test_asm_file, use_kubeconfig=False)
        assert m.last_request.json() == assembly._add_last_applied_configuration_annotation(test_asm)


def test_create_assemblies_from_file_creates_one_assembly_k8s_api(k8s):
    mock_create_assemblies(k8s)
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)

    assert assembly.create_assemblies_from_file(namespace='test_ns', filepath=test_asm_file, use_kubeconfig=True)

    k8s.assemblies.create.assert_called_once_with(
        body=pyk8s.ResourceItem.parse_obj(assembly._add_last_applied_configuration_annotation(test_asm)), 
        namespace='test_ns')


def test_create_assembley_from_file_assembly_already_exists(mocker, capfd, k8s):
    mock_list_assemblies(k8s)
    
    # mock the Kubernetes create function to return error upon creation of test_asm, success for test_asm2
    k8s.assemblies.create.side_effect = partial(mock_return_conflict_kube, status_code=409, error_message='deploy failed',
                                                detail_message='assemblies.insights.kx.com sdk-sample-assembly already exists')


    assert assembly.create_assemblies_from_file(namespace='test_ns', filepath=test_asm_file, use_kubeconfig=True) == []
    out, err = capfd.readouterr()
    assert out == f"Submitting assembly from {test_asm_file}\nError: deploy failed. assemblies.insights.kx.com sdk-sample-assembly already exists\n"

def test_create_assembley_from_file_assembly_already_exists_kube(mocker, capfd, k8s):
    mock_list_assemblies(k8s)
    # mock the Kubernetes create function to return error upon creation of test_asm, success for test_asm2
    k8s.assemblies.create.side_effect = partial(mock_return_conflict_kube, status_code=409, error_message='deploy failed',
                                                                        detail_message='assemblies.insights.kx.com sdk-sample-assembly already exists')

    assert assembly.create_assemblies_from_file(namespace='test_ns', filepath=test_asm_file, use_kubeconfig=True) == []
    out, err = capfd.readouterr()
    assert out == f"Submitting assembly from {test_asm_file}\nError: deploy failed. assemblies.insights.kx.com sdk-sample-assembly already exists\n"


def test_create_assemblies_from_file_creates_two_assemblies(mocker, k8s):
    mocker.patch('kxicli.common.get_access_token', utils.return_none)
    mock_list_assemblies(k8s)

    # Call backup_assemblies to create file
    with temp_asm_file() as test_asm_list_file, requests_mock.Mocker() as m:
        m.post('https://test.kx.com/kxicontroller/assembly/cli/deploy')
        assert assembly.backup_assemblies(namespace='test_ns', filepath=test_asm_list_file, force=False) == test_asm_list_file
        assert assembly.create_assemblies_from_file(hostname='https://test.kx.com', client_id='client', client_secret='secret', \
                                                realm='insights', namespace=None, filepath=test_asm_list_file, use_kubeconfig=False)

        with open(test_asm_list_file, 'rb') as f:
            assert yaml.full_load(f) == ASSEMBLY_BACKUP_LIST
        history = m.request_history
        assert len(m.request_history) == 2
        assert history[0].json() == assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME, False))
        assert history[1].json() == assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME2, False))


def test_create_assemblies_from_file_creates_two_assemblies_k8s_api(k8s):
    mock_list_assemblies(k8s)
    mock_create_assemblies(k8s)

    # Call backup_assemblies to create file
    with temp_asm_file() as test_asm_list_file:
        assert assembly.backup_assemblies(namespace='test_ns', filepath=test_asm_list_file, force=False) == test_asm_list_file
        assert assembly.create_assemblies_from_file(namespace='test_ns', filepath=test_asm_list_file, use_kubeconfig=True)

        with open(test_asm_list_file, 'rb') as f:
            assert yaml.full_load(f) == ASSEMBLY_BACKUP_LIST
        k8s.assemblies.create.assert_has_calls([
            call(body=pyk8s.ResourceItem.parse_obj(assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME, False))), 
                 namespace='test_ns'),
            call(body=pyk8s.ResourceItem.parse_obj(assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME2, False))), 
                 namespace='test_ns')
        ])


def test_create_assemblies_from_file_removes_resourceVersion(mocker, k8s):
    TEST_ASSEMBLY_WITH_resourceVersion = build_assembly_object(ASM_NAME, True)
    TEST_ASSEMBLY_WITH_resourceVersion['metadata']['resourceVersion'] = '01234'

    assembly_list = [TEST_ASSEMBLY_WITH_resourceVersion]
    mocker.patch('kxicli.common.get_access_token', utils.return_none)
    mock_list_assemblies(k8s, response=assembly_list)

    # Call backup_assemblies to create file
    with temp_asm_file() as test_asm_list_file, requests_mock.Mocker() as m:
        m.post('https://test.kx.com/kxicontroller/assembly/cli/deploy')
        assert assembly.backup_assemblies(namespace='test_ns', filepath=test_asm_list_file, force=False) == test_asm_list_file
        assembly.create_assemblies_from_file(hostname='https://test.kx.com', client_id='client', client_secret='secret', \
                                                realm='insights', namespace=None, filepath=test_asm_list_file, use_kubeconfig=False)
        assert m.last_request.json() == assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME, False))


def test_create_assemblies_from_file_removes_resourceVersion_k8s_api(mocker, k8s):
    TEST_ASSEMBLY_WITH_resourceVersion = build_assembly_object(ASM_NAME, True)
    TEST_ASSEMBLY_WITH_resourceVersion['metadata']['resourceVersion'] = '01234'

    assembly_list = [TEST_ASSEMBLY_WITH_resourceVersion]
    mock_list_assemblies(k8s, response=assembly_list)
    mock_create_assemblies(k8s)

    # Call backup_assemblies to create file
    with temp_asm_file() as test_asm_list_file:
        assert assembly.backup_assemblies(namespace='test_ns', filepath=test_asm_list_file, force=False) == test_asm_list_file
        assert assembly.create_assemblies_from_file(namespace='test_ns', filepath=test_asm_list_file, use_kubeconfig=True)
        k8s.assemblies.create.assert_has_calls([
            call(
                body=pyk8s.ResourceItem.parse_obj(assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME, False))), 
                namespace='test_ns'),
        ])

def test_create_assemblies_from_file_creates_when_one_already_exists_k8s_api(mocker, k8s):
    # when applying one assembly fails, applying others proceeds uninterrupted
    mock_list_assemblies(k8s)
    # mock the Kubernetes create function to return error upon creation of test_asm, success for test_asm2
    k8s.assemblies.create.side_effect = mock_return_conflict_for_assembly_k8s


    # Call backup_assemblies to create file
    with temp_asm_file() as test_asm_list_file:
        assert assembly.backup_assemblies(namespace='test_ns', filepath=test_asm_list_file, force=False)  == test_asm_list_file
        assert assembly.create_assemblies_from_file(namespace='test_ns', filepath=test_asm_list_file, use_kubeconfig=True)

        with open(test_asm_list_file, 'rb') as f:
            assert yaml.full_load(f) == ASSEMBLY_BACKUP_LIST
        k8s.assemblies.create.assert_has_calls([
            call(body=pyk8s.ResourceItem.parse_obj(assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME2))), 
                 namespace='test_ns'),
        ])


def test_create_assemblies_from_file_does_nothing_when_filepath_is_none():
    assert assembly.create_assemblies_from_file(namespace='test_ns', filepath=None, use_kubeconfig=False) == []


def test_delete_assembly(mocker):
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.post(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}/teardown')
        assert assembly._delete_assembly(hostname='https://test.kx.com',
            client_id='client',
            client_secret='secret',
            realm='insights',
            name=ASM_NAME,
            use_kubeconfig=False,
            force=True
        ) == True


def test_delete_assembly_k8s_api(k8s):

    assert assembly._delete_assembly(
        namespace='test_ns',
        name=ASM_NAME,
        wait=False,
        force=True,
        use_kubeconfig=True
    ) == True

    k8s.assemblies.delete.assert_has_calls([
            call(ASM_NAME, namespace='test_ns'),
        ])
    

def test_delete_error_assembly_k8s_api(k8s):
    k8s.assemblies.delete.side_effect = Exception("test message")
    assert assembly._delete_assembly(
        namespace='test_ns',
        name=ASM_NAME,
        wait=False,
        force=True,
        use_kubeconfig=True
    ) == False

    k8s.assemblies.delete.assert_has_calls([
            call(ASM_NAME, namespace='test_ns'),
        ])


def test_delete_running_assemblies(k8s):
    mock_list_assemblies(k8s)

    assert assembly.delete_running_assemblies(namespace='test_ns', wait=False, force=True) == [True, True, True]

    k8s.assemblies.delete.assert_has_calls([
            call(ASM_NAME, namespace='test_ns'),
            call(ASM_NAME2, namespace='test_ns'),
            call(ASM_NAME3, namespace='test_ns'),
    ])


def test_read_assembly_file_returns_contents():
    assert assembly._read_assembly_file(test_asm_file) == test_asm


def test_read_assembly_file_errors_when_file_does_not_exist():
    with pytest.raises(Exception) as e:
        assembly._read_assembly_file('a_bad_file_name.yaml')
    assert isinstance(e.value, click.ClickException)
    assert 'File not found: a_bad_file_name.yaml' in e.value.message


def test_read_assembly_file_errors_when_file_is_invalid():
    with temp_asm_file(file_name='new_file') as new_file:
        with open(new_file, 'w') as f:
            f.write('test: {this is not a yaml')
        with pytest.raises(Exception) as e:
            assembly._read_assembly_file(new_file)
        assert isinstance(e.value, click.ClickException)
        assert f'Invalid assembly file {new_file}' in e.value.message


def test_get_preferred_api_version_raises_exception_with_no_version(k8s):
    k8s.assemblies = None
    with pytest.raises(Exception) as e:
        assembly.get_preferred_api_version(PREFERRED_VERSION)
    assert isinstance(e.value, click.ClickException)
    assert f'Could not find preferred API version for group {PREFERRED_VERSION}' in e.value.message


# CLI invoked tests

def test_cli_assembly_status_if_assembly_not_deployed(mocker, k8s):
    # mock the kxic API to return an empty assembly
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.get(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}')
        result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', ASM_NAME])

    assert result.output == 'Error: Assembly not yet deployed\n'
    assert result.exit_code == 1


def test_cli_assembly_status_if_assembly_not_deployed_k8s_api(k8s):
    # mock the Kubernetes function to return an empty assembly
    k8s.assemblies.read.return_value = {}

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', 'test_asm', '--use-kubeconfig'])
    assert result.output == 'Error: Assembly not yet deployed\n'
    assert result.exit_code == 1


def test_cli_assembly_status_if_assembly_deployed(mocker, k8s):
    # mock the Kubernetes function to return TEST_ASSEMBLY
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.get(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}', text=json.dumps(build_assembly_object_kxic(ASM_NAME)))
        result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', ASM_NAME])

    assert result.exit_code == 0
    assert result.output == f'{json.dumps(build_assembly_object_kxic(ASM_NAME),indent=2)}\n'


def test_cli_assembly_status_if_assembly_deployed_k8s_api(mocker, k8s):
    # mock the Kubernetes function to return TEST_ASSEMBLY
    k8s.assemblies.read.return_value = build_assembly_object(ASM_NAME, True)

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', 'test_asm', '--use-kubeconfig'])

    assert result.exit_code == 0
    assert result.output == f'{json.dumps(TRUE_STATUS, indent=2)}\n'


def test_cli_assembly_status_with_false_status(mocker, k8s):
    # set False status
    asm = build_assembly_object_kxic(ASM_NAME, ready=False)

    # mock the kxic API function to return asm above
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.get(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}', text=json.dumps(asm))
        result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', ASM_NAME])

    assert result.exit_code == 0
    assert result.output == f'{json.dumps(asm, indent=2)}\n'


def test_cli_assembly_status_with_false_status_k8s_api(mocker, k8s):
    # set False status
    asm = build_assembly_object(ASM_NAME, True)
    asm['status']['conditions'][0]['status'] = 'False'

    # mock the Kubernetes function to return asm above
    k8s.assemblies.read.return_value = asm

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', 'test_asm', '--use-kubeconfig'])

    assert result.exit_code == 0
    assert result.output == f'{json.dumps(FALSE_STATUS, indent=2)}\n'


def test_cli_assembly_status_with_not_found_exception(mocker, k8s):
    # mock kxic API to return a not found status
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.get(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}', status_code=404)
        result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', ASM_NAME])

    assert result.exit_code == 1
    assert result.output == f'Error: Assembly {ASM_NAME} not found\n'


def test_cli_assembly_status_with_not_found_exception_k8s_api(k8s):
    # mock Kubernetes get API to raise a not found exception
    k8s.assemblies.read.side_effect = pyk8s.exceptions.NotFoundError(MagicMock())

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', ASM_NAME, '--use-kubeconfig'])

    assert result.exit_code == 1
    assert result.output == f'Error: Assembly {ASM_NAME} not found\n'


def test_cli_assembly_status_with_wait_for_ready(mocker, k8s):
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.get(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}', text=json.dumps(build_assembly_object_kxic(ASM_NAME)))
        result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', ASM_NAME, '--wait-for-ready'])

    assert result.exit_code == 0
    assert result.output == f"""Waiting for assembly to enter "Ready" state
{json.dumps(build_assembly_object_kxic(ASM_NAME), indent=2)}
"""


def test_cli_assembly_status_with_wait_for_ready_k8s_api(k8s):
    k8s.assemblies.read.return_value = build_assembly_object(ASM_NAME, True)

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', ASM_NAME, '--wait-for-ready', '--use-kubeconfig'])

    assert result.exit_code == 0
    assert result.output == f"""Waiting for assembly to enter "Ready" state
{json.dumps(TRUE_STATUS, indent=2)}\n"""


def test_cli_assembly_teardown_without_confirm(k8s):
    # answer 'n' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME], input='n')

    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Are you sure you want to teardown {ASM_NAME} [y/N]: n
Not tearing down assembly {ASM_NAME}\n"""


def test_cli_assembly_teardown_with_confirm(mocker, k8s):
    # API response to do nothing
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.post(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}/teardown')
        result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME], input='y')

    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Are you sure you want to teardown {ASM_NAME} [y/N]: y
"""

def test_cli_assembly_teardown_with_confirm_k8s_api(mocker, k8s):
    # mock Kubernetes delete API to do nothing
    k8s.assemblies.delete.return_value = {}
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME, '--use-kubeconfig'], input='y')

    k8s.assemblies.delete.assert_has_calls([
            call(ASM_NAME, namespace=utils.namespace()),
        ])
    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Are you sure you want to teardown {ASM_NAME} [y/N]: y
"""

def test_cli_assembly_teardown_with_not_found_exception(mocker, k8s):
    # mock kxi API to return a not found exception
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.post(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}/teardown', status_code=404)
        result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME], input='y')

    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Are you sure you want to teardown {ASM_NAME} [y/N]: y
Ignoring teardown, {ASM_NAME} not found
"""


def test_cli_assembly_teardown_with_not_found_exception_k8s_api(k8s, mocker):
    # mock Kubernetes delete API to raise a not found exception
    k8s.assemblies.delete.side_effect = raise_not_found
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME, '--use-kubeconfig'], input='y')

    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Are you sure you want to teardown {ASM_NAME} [y/N]: y
Ignoring teardown, {ASM_NAME} not found
"""

def test_cli_assembly_teardown_with_force_and_wait(mocker, k8s):
    # mock kxi teardown API to do nothing and the get status api to return a not found exception
    # i.e that the deleted assembly no longer exists
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.post(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}/teardown')
        m.get(f'https://test.kx.com/kxicontroller/assembly/cli/{ASM_NAME}', status_code=404)

        result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME, '--force', '--wait'])

    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Waiting for assembly to be torn down
"""


def test_cli_assembly_teardown_with_force_and_wait_k8s_api(k8s, mocker):
    # mock Kubernetes delete API to do nothing and the get api to raise a not found exception
    # i.e that the deleted assembly no longer exists
    k8s.assemblies.delete.return_value = {}
    k8s.assemblies.read.side_effect = raise_not_found
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME, '--force', '--wait', '--use-kubeconfig'])

    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Waiting for assembly to be torn down
"""


def test_cli_assembly_list_if_assembly_deployed(mocker, k8s):
    # mock the requests API return TEST_ASSEMBLY
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.get('https://test.kx.com/kxicontroller/assembly/',
            text=json.dumps([
                build_assembly_object_kxic(ASM_NAME, running=True, ready=True),
                build_assembly_object_kxic(ASM_NAME2, running=False, ready=False)
                ]
            )
        )
        result = TEST_CLI.invoke(main.cli, ['assembly', 'list'])

    assert result.exit_code == 0
    assert result.output == f"""ASSEMBLY NAME  RUNNING  READY
{ASM_NAME}       True     True
{ASM_NAME2}      False    False
"""

def test_cli_assembly_list_if_assembly_deployed_k8s_api(k8s):
    # mock the Kubernetes function to return TEST_ASSEMBLY
    k8s.assemblies.get.return_value = [build_assembly_object(ASM_NAME, True)]

    result = TEST_CLI.invoke(main.cli, ['assembly', 'list', '--use-kubeconfig'])

    assert result.exit_code == 0
    assert result.output == f"""ASSEMBLY NAME  NAMESPACE
{ASM_NAME}       {TEST_NS}
"""


def test_cli_assembly_list_error_response(mocker, k8s):
    mocker.patch('kxicli.commands.assembly._list_assemblies', utils.return_false)
    result = TEST_CLI.invoke(main.cli, ['assembly', 'list'])
    assert result.exit_code == 1


def test_cli_assembly_deploy_from_file(mocker, k8s):
    # mock requests post to capture payload
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.post('https://test.kx.com/kxicontroller/assembly/cli/deploy')

        result = TEST_CLI.invoke(main.cli, ['assembly', 'deploy', '--filepath', test_asm_file])
        assert m.last_request.json() == assembly._add_last_applied_configuration_annotation(test_asm)

    assert result.exit_code == 0
    assert result.output == f"""Using assembly.filepath from command line option: {test_asm_file}
Submitting assembly from {test_asm_file}
Custom assembly resource basic-assembly created!
"""


def test_cli_assembly_deploy_from_file_k8s_api(mocker, k8s):
    mock_create_assemblies(k8s)

    result = TEST_CLI.invoke(main.cli, ['assembly', 'deploy', '-f', test_asm_file, '--use-kubeconfig'])

    assert result.exit_code == 0
    assert result.output == f"""Using assembly.filepath from command line option: {test_asm_file}
Submitting assembly from {test_asm_file}
Custom assembly resource basic-assembly created!
"""

    k8s.assemblies.create.assert_has_calls([
            call(
                body=pyk8s.ResourceItem.parse_obj(assembly._add_last_applied_configuration_annotation(test_asm)), 
                namespace="test-namespace"),
    ])


def test_cli_assembly_create_from_file(mocker, k8s):
    # Test the 'create' alias of the 'deploy' command
    # mock requests post to capture payload
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.post('https://test.kx.com/kxicontroller/assembly/cli/deploy')

        result = TEST_CLI.invoke(main.cli, ['assembly', 'create', '--filepath', test_asm_file])
        assert m.last_request.json() == assembly._add_last_applied_configuration_annotation(test_asm)

    assert result.exit_code == 0
    assert result.output == f"""Using assembly.filepath from command line option: {test_asm_file}
Submitting assembly from {test_asm_file}
Custom assembly resource basic-assembly created!
"""

def test_cli_assembly_deploy_with_context_not_set(mocker, k8s):
    # When context is not set, the default namespace is taken from cli-config
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.post('https://test.kx.com/kxicontroller/assembly/cli/deploy')
        result = TEST_CLI.invoke(main.cli, ['assembly', 'deploy', '-f', test_asm_file])
        assert m.last_request.json() == assembly._add_last_applied_configuration_annotation(test_asm)

    assert result.exit_code == 0
    assert result.output == f"""Using assembly.filepath from command line option: {test_asm_file}
Submitting assembly from {test_asm_file}
Custom assembly resource basic-assembly created!
"""


def test_cli_assembly_deploy_with_context_not_set_k8s_api(mocker, k8s):
    # When context is not set, the default namespace is taken from cli-config
    mock_create_assemblies(k8s)
    k8s.config.namespace = None

    result = TEST_CLI.invoke(main.cli, ['assembly', 'deploy', '--filepath', test_asm_file, '--use-kubeconfig'])

    assert result.exit_code == 0
    assert result.output == f"""Using assembly.filepath from command line option: {test_asm_file}
Submitting assembly from {test_asm_file}
Using namespace from config file {common.config.config_file}: test
Custom assembly resource basic-assembly created!
"""
    k8s.assemblies.create.assert_has_calls([
            call(
                body=pyk8s.ResourceItem.parse_obj(assembly._add_last_applied_configuration_annotation(test_asm)), 
                namespace="test"),
    ])


def test_cli_assembly_deploy_and_wait(mocker, k8s):
    mocker.patch('kxicli.common.get_access_token', utils.return_none)
    mocker.patch('kxicli.commands.assembly._assembly_status', utils.return_true)
    with requests_mock.Mocker() as m:
        m.post('https://test.kx.com/kxicontroller/assembly/cli/deploy')
        result = TEST_CLI.invoke(main.cli, ['assembly', 'deploy', '--filepath', test_asm_file, '--wait'])
        assert m.last_request.json() == assembly._add_last_applied_configuration_annotation(test_asm)

    assert result.exit_code == 0
    assert result.output == f"""Using assembly.filepath from command line option: {test_asm_file}
Submitting assembly from {test_asm_file}
Waiting for assembly to enter "Ready" state
Custom assembly resource basic-assembly created!
"""


def test_cli_assembly_deploy_and_wait_k8s_api(mocker, k8s):
    mock_create_assemblies(k8s)
    k8s.assemblies.read.return_value = build_assembly_object(ASM_NAME, True)

    result = TEST_CLI.invoke(main.cli, ['assembly', 'deploy', '-f', test_asm_file, '--wait', '--use-kubeconfig'])

    assert result.exit_code == 0
    assert result.output == f"""Using assembly.filepath from command line option: {test_asm_file}
Submitting assembly from {test_asm_file}
Waiting for assembly to enter "Ready" state
Custom assembly resource basic-assembly created!
"""
    k8s.assemblies.create.assert_has_calls([
            call(body=pyk8s.ResourceItem.parse_obj(assembly._add_last_applied_configuration_annotation(test_asm)), 
                 namespace="test-namespace"),
    ])

def test_cli_assembly_deploy_without_filepath(mocker, k8s):
    mocker.patch('kxicli.common.is_interactive_session', utils.return_false)
    result = TEST_CLI.invoke(main.cli, ['assembly', 'deploy'])
    assert result.exit_code == 1
    assert result.output == f'Error: Could not find expected option. Please set command line argument (\'-f\', \'--filepath\') or configuration value assembly.filepath in config file {common.config.config_file}\n'


def test_cli_assembly_deploy_without_filepath_interactive_session(mocker, k8s):
    mocker.patch('kxicli.common.is_interactive_session', utils.return_true)
    with requests_mock.Mocker() as m:
        mocker.patch('kxicli.common.get_access_token', utils.return_none)
        m.post('https://test.kx.com/kxicontroller/assembly/cli/deploy')
        result = TEST_CLI.invoke(main.cli, ['assembly', 'deploy'], input=test_asm_file)
        assert m.last_request.json() == assembly._add_last_applied_configuration_annotation(test_asm)

    assert result.exit_code == 0
    assert result.output == f"""Please enter a path to the assembly file: {test_asm_file}
Submitting assembly from {test_asm_file}
Custom assembly resource basic-assembly created!
"""


def test_cli_assembly_backup_assemblies(k8s):
    mock_list_assemblies(k8s)

    with temp_asm_file() as test_asm_list_file:
        result = TEST_CLI.invoke(main.cli, ['assembly', 'backup', '--filepath', test_asm_list_file])

        assert result.exit_code == 0
        assert result.output == f"""warn=Refusing to backup assemblies: ['{ASM_NAME3}']. These assemblies are missing 'kubectl.kubernetes.io/last-applied-configuration' annotation. Please restart these assemblies manually.
Persisted assembly definitions for ['{ASM_NAME}', '{ASM_NAME2}'] to {test_asm_list_file}
"""
        with open(test_asm_list_file, 'rb') as f:
            expect = yaml.full_load(f)
            assert expect == ASSEMBLY_BACKUP_LIST


def test_cli_assembly_backup_assemblies_overwrites_when_file_already_exists(k8s):
    mock_list_assemblies(k8s)
    with temp_asm_file() as test_asm_list_file:
        with open(test_asm_list_file, 'w') as f:
            f.write('a test file')

        # Respond 'y' to the prompt to overwrite
        result = TEST_CLI.invoke(main.cli, ['assembly', 'backup', '-f', test_asm_list_file], input='y')

        assert result.exit_code == 0
        assert result.output == f"""
{test_asm_list_file} file exists. Do you want to overwrite it with a new assembly backup file? [y/N]: y
warn=Refusing to backup assemblies: ['{ASM_NAME3}']. These assemblies are missing 'kubectl.kubernetes.io/last-applied-configuration' annotation. Please restart these assemblies manually.
Persisted assembly definitions for ['{ASM_NAME}', '{ASM_NAME2}'] to {test_asm_list_file}
"""
        with open(test_asm_list_file, 'rb') as f:
            assert yaml.full_load(f) == ASSEMBLY_BACKUP_LIST


def test_cli_assembly_backup_assemblies_creates_new_when_file_already_exists(k8s):
    mock_list_assemblies(k8s)
    with temp_asm_file() as test_asm_list_file, temp_asm_file(file_name='new_backup.yaml') as new_file:
        with open(test_asm_list_file, 'w') as f:
            f.write('another test file')

        # Provide new file to prompt
        user_input = f"""n
{new_file}
"""
        result = TEST_CLI.invoke(main.cli, ['assembly', 'backup', '--filepath', test_asm_list_file], input=user_input)

        assert result.exit_code == 0
        assert result.output == f"""
{test_asm_list_file} file exists. Do you want to overwrite it with a new assembly backup file? [y/N]: n
Please enter the path to write the assembly backup file: {new_file}
warn=Refusing to backup assemblies: ['{ASM_NAME3}']. These assemblies are missing 'kubectl.kubernetes.io/last-applied-configuration' annotation. Please restart these assemblies manually.
Persisted assembly definitions for ['{ASM_NAME}', '{ASM_NAME2}'] to {new_file}
"""
        with open(new_file, 'rb') as f:
            assert yaml.full_load(f) == ASSEMBLY_BACKUP_LIST


def test_cli_assembly_backup_assemblies_forces_overwrite_when_file_already_exists(k8s):
    mock_list_assemblies(k8s)
    with temp_asm_file() as test_asm_list_file:
        with open(test_asm_list_file, 'w') as f:
            f.write('yet another test file')

        result = TEST_CLI.invoke(main.cli, ['assembly', 'backup', '-f', test_asm_list_file, '--force'])

        assert result.exit_code == 0
        assert result.output == f"""warn=Refusing to backup assemblies: ['{ASM_NAME3}']. These assemblies are missing 'kubectl.kubernetes.io/last-applied-configuration' annotation. Please restart these assemblies manually.
Persisted assembly definitions for ['{ASM_NAME}', '{ASM_NAME2}'] to {test_asm_list_file}
"""
        with open(test_asm_list_file, 'rb') as f:
            assert yaml.full_load(f) == ASSEMBLY_BACKUP_LIST
