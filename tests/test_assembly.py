import click
import copy
import json
import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp

import kubernetes as k8s
import pytest
import yaml
from click.testing import CliRunner

from kxicli import common
from kxicli import main
from kxicli.commands import assembly
from utils import return_true, return_false

ASM_NAME = 'test_asm'
ASM_NAME2 = 'test_asm2'
ASM_NAME3 = 'test_asm3'
TEST_CLI = CliRunner()
CUSTOM_OBJECT_API = 'kubernetes.client.CustomObjectsApi'
PREFERRED_VERSION_FUNC = 'kxicli.commands.assembly.get_preferred_api_version'
PREFERRED_VERSION = 'v1'
TEST_NS = 'test_ns'
test_asm_file = os.path.dirname(__file__) + '/files/assembly-v1.yaml'

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


ASSEMBLY_LIST = {'items': [build_assembly_object(ASM_NAME, True), build_assembly_object(ASM_NAME2, True), build_assembly_object(ASM_NAME3)]}
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


def raise_not_found(**kwargs):
    """Helper function to test try/except blocks"""
    raise k8s.client.rest.ApiException(status=404)


def mocked_return_false(name):
    return False


def store_args(**args):
    global stored_args
    stored_args = args


def append_args(**args):
    global appended_args
    appended_args.append(args)


def mock_return_conflict_for_assembly(**kwargs):
    global appended_args
    if kwargs['body']['metadata']['name'] == ASM_NAME:
        raise k8s.client.rest.ApiException(status=409)
    else:
        appended_args.append(kwargs)


# mock the response from the Kubernetes list function
def mock_list_assemblies(mock_instance, response=ASSEMBLY_LIST):
    mock_instance.list_namespaced_custom_object.return_value = response


# mock the Kubernetes create function to capture arguments
def mock_create_assemblies(mock_instance):
    global appended_args
    appended_args = []
    mock_instance.create_namespaced_custom_object.side_effect = append_args


def mock_delete_assemblies(mock_instance):
    global appended_args
    appended_args = []
    mock_instance.delete_namespaced_custom_object.side_effect = append_args


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
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = build_assembly_object(ASM_NAME, True)
    assert assembly._assembly_status(namespace='test_ns', name='test_asm')


def test_status_with_false_status(mocker):
    # set False status
    asm = build_assembly_object(ASM_NAME, True)
    asm['status']['conditions'][0]['status'] = 'False'

    # mock the Kubernetes function to return asm above
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = asm

    assert assembly._assembly_status(namespace='test_ns', name='test_asm', print_status=True) == False


def test_create_with_false_status(mocker):
    # set False status
    asm = build_assembly_object(ASM_NAME, True)
    asm['status']['conditions'][0]['status'] = 'False'

    # mock the Kubernetes function to return asm above
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = asm

    assert assembly._assembly_status(namespace='test_ns', name='test_asm', print_status=True) == False


def test_get_assemblies_list(mocker):
    mock_list_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
    assert assembly._get_assemblies_list(namespace='test_ns') == ASSEMBLY_LIST


def test_get_assemblies_list_uses_label_selector(mocker):
    mock = mocker.patch.object(k8s.client.CustomObjectsApi, 'list_namespaced_custom_object')
    mock.side_effect = lambda *args, **kwargs: ASSEMBLY_LIST
    res = assembly._get_assemblies_list(namespace='test_ns')

    assert mock.call_args_list[0][1]['label_selector'] == assembly.ASM_LABEL_SELECTOR
    assert res == ASSEMBLY_LIST


def test_backup_assemblies(mocker):
    mock_list_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
    with temp_asm_file() as test_asm_list_file:
        assert test_asm_list_file == assembly._backup_assemblies(namespace='test_ns', filepath=test_asm_list_file,
                                                                 force=False)
        with open(test_asm_list_file, 'rb') as f:
            expect = yaml.full_load(f)
            assert expect == ASSEMBLY_BACKUP_LIST


def test_backup_assemblies_when_no_assemblies_running(mocker):
    mock_instance = mocker.patch(CUSTOM_OBJECT_API).return_value
    mock_instance.list_namespaced_custom_object.return_value = {'items': []}
    with temp_asm_file() as test_asm_list_file:
        assert assembly._backup_assemblies(namespace='test_ns', filepath=test_asm_list_file, force=False) == None
        assert not os.path.exists(test_asm_list_file)


def test_add_last_applied_configuration_annotation():
    test_assembly = build_assembly_object(ASM_NAME)
    res = assembly._add_last_applied_configuration_annotation(test_assembly)
    assert assembly.CONFIG_ANNOTATION in res['metadata']['annotations']
    test_assembly['metadata']['annotations'] = {}
    assert res['metadata']['annotations'][assembly.CONFIG_ANNOTATION] == '\n' + json.dumps(test_assembly)


def test_create_assembly_submits_to_k8s_api(mocker):
    mock_create_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)

    assert assembly._create_assembly(namespace='test_ns', body=test_asm)

    assert appended_args == [
        {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test_ns', 'plural': 'assemblies',
         'body': assembly._add_last_applied_configuration_annotation(test_asm)}]


def test_create_assemblies_from_file_creates_one_assembly(mocker):
    mock_create_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)

    assert assembly._create_assemblies_from_file(namespace='test_ns', filepath=test_asm_file)

    assert appended_args == [
        {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test_ns', 'plural': 'assemblies',
         'body': assembly._add_last_applied_configuration_annotation(test_asm)}]


def test_create_assemblies_from_file_creates_two_assemblies(mocker):
    mock_instance = mocker.patch(CUSTOM_OBJECT_API).return_value
    mock_list_assemblies(mock_instance)
    mock_create_assemblies(mock_instance)

    # Call _backup_assemblies to create file
    with temp_asm_file() as test_asm_list_file:
        assert assembly._backup_assemblies(namespace='test_ns', filepath=test_asm_list_file, force=False) == test_asm_list_file
        assert assembly._create_assemblies_from_file(namespace='test_ns', filepath=test_asm_list_file)

        with open(test_asm_list_file, 'rb') as f:
            assert yaml.full_load(f) == ASSEMBLY_BACKUP_LIST
        assert appended_args == [
            {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test_ns', 'plural': 'assemblies',
             'body': assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME, False))},
            {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test_ns', 'plural': 'assemblies',
             'body': assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME2, False))}
        ]


def test_create_assemblies_from_file_removes_resourceVersion(mocker):
    TEST_ASSEMBLY_WITH_resourceVersion = build_assembly_object(ASM_NAME, True)
    TEST_ASSEMBLY_WITH_resourceVersion['metadata']['resourceVersion'] = '01234'

    assembly_list = {'items': [TEST_ASSEMBLY_WITH_resourceVersion]}
    mock_instance = mocker.patch(CUSTOM_OBJECT_API).return_value
    mock_list_assemblies(mock_instance=mock_instance, response=assembly_list)
    mock_create_assemblies(mock_instance)

    # Call _backup_assemblies to create file
    with temp_asm_file() as test_asm_list_file:
        assert assembly._backup_assemblies(namespace='test_ns', filepath=test_asm_list_file, force=False) == test_asm_list_file
        assert assembly._create_assemblies_from_file(namespace='test_ns', filepath=test_asm_list_file)

        assert appended_args == [
            {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test_ns', 'plural': 'assemblies',
             'body': assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME, False))}]


def test_create_assemblies_from_file_creates_when_one_already_exists(mocker):
    # when applying one assembly fails, applying others proceeds uninterrupted
    mock_instance = mocker.patch(CUSTOM_OBJECT_API).return_value
    mock_list_assemblies(mock_instance)
    global appended_args
    appended_args = []
    # mock the Kubernetes create function to return error upon creation of test_asm, success for test_asm2
    mock_instance.create_namespaced_custom_object.side_effect = mock_return_conflict_for_assembly

    # Call _backup_assemblies to create file
    with temp_asm_file() as test_asm_list_file:
        assert assembly._backup_assemblies(namespace='test_ns', filepath=test_asm_list_file, force=False)  == test_asm_list_file
        assert assembly._create_assemblies_from_file(namespace='test_ns', filepath=test_asm_list_file)

        with open(test_asm_list_file, 'rb') as f:
            assert yaml.full_load(f) == ASSEMBLY_BACKUP_LIST
        assert appended_args == [
            {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test_ns', 'plural': 'assemblies',
             'body': assembly._add_last_applied_configuration_annotation(build_assembly_object(ASM_NAME2))}
        ]


def test_create_assemblies_from_file_does_nothing_when_filepath_is_none():
    assert assembly._create_assemblies_from_file(namespace='test_ns', filepath=None) == []


def test_delete_assembly(mocker):
    mock_instance = mocker.patch(CUSTOM_OBJECT_API).return_value
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)
    mock_delete_assemblies(mock_instance)

    assert assembly._delete_assembly(namespace='test_ns', name=ASM_NAME, wait=False, force=True) == True

    assert appended_args == [
        {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test_ns', 'plural': 'assemblies',
         'name': ASM_NAME}
    ]


def test_delete_running_assemblies(mocker):
    mock_instance = mocker.patch(CUSTOM_OBJECT_API).return_value
    mock_list_assemblies(mock_instance)
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)
    mock_delete_assemblies(mock_instance)

    assert assembly._delete_running_assemblies(namespace='test_ns', wait=False, force=True) == [True, True, True]

    assert appended_args == [
        {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test_ns', 'plural': 'assemblies',
         'name': ASM_NAME},
        {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test_ns', 'plural': 'assemblies',
         'name': ASM_NAME2},
        {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test_ns', 'plural': 'assemblies',
         'name': ASM_NAME3}
    ]


def test_read_assembly_file_returns_contents():
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)
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


def test_get_preferred_api_version_raises_exception_with_no_version(mocker):
    mock = mocker.patch('kubernetes.client.ApisApi')
    mock.get_api_versions.return_value = {}
    with pytest.raises(Exception) as e:
        assembly.get_preferred_api_version(PREFERRED_VERSION)
    assert isinstance(e.value, click.ClickException)
    assert f'Could not find preferred API version for group {PREFERRED_VERSION}' in e.value.message


# CLI invoked tests

def test_cli_assembly_status_if_assembly_not_deployed(mocker):
    # mock the Kubernetes function to return an empty assembly
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = {}

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', 'test_asm'])
    assert result.output == 'Error: Assembly not yet deployed\n'
    assert result.exit_code == 1


def test_cli_assembly_status_if_assembly_deployed(mocker):
    # mock the Kubernetes function to return TEST_ASSEMBLY
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = build_assembly_object(ASM_NAME, True)

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', 'test_asm'])

    assert result.exit_code == 0
    assert result.output == f'{json.dumps(TRUE_STATUS, indent=2)}\n'


def test_cli_assembly_status_with_false_status(mocker):
    # set False status
    asm = build_assembly_object(ASM_NAME, True)
    asm['status']['conditions'][0]['status'] = 'False'

    # mock the Kubernetes function to return asm above
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = asm

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', 'test_asm'])

    assert result.exit_code == 0
    assert result.output == f'{json.dumps(FALSE_STATUS, indent=2)}\n'


def test_cli_assembly_status_with_not_found_exception(mocker):
    # mock Kubernetes get API to raise a not found exception
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.side_effect = raise_not_found

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', ASM_NAME])

    assert result.exit_code == 1
    assert result.output == f'Error: Assembly {ASM_NAME} not found\n'


def test_cli_assembly_status_with_wait_for_ready(mocker):
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = build_assembly_object(ASM_NAME, True)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', ASM_NAME, '--wait-for-ready'])

    assert result.exit_code == 0
    assert result.output == f"""Waiting for assembly to enter "Ready" state
{json.dumps(TRUE_STATUS, indent=2)}\n"""


def test_cli_assembly_teardown_without_confirm():
    # answer 'n' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME], input='n')

    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Are you sure you want to teardown {ASM_NAME} [y/N]: n
Not tearing down assembly {ASM_NAME}\n"""


def test_cli_assembly_teardown_with_confirm(mocker):
    # mock Kubernetes delete API to do nothing
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.delete_namespaced_custom_object.return_value = {}
    instance.delete_namespaced_custom_object.side_effect = store_args
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'delete', '--name', ASM_NAME], input='y')

    assert stored_args == {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test',
                           'plural': 'assemblies', 'name': ASM_NAME}
    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Are you sure you want to teardown {ASM_NAME} [y/N]: y
"""


def test_cli_assembly_teardown_with_confirm(mocker):
    # mock Kubernetes delete API to do nothing
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.delete_namespaced_custom_object.return_value = {}
    instance.delete_namespaced_custom_object.side_effect = store_args
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME], input='y')

    assert stored_args == {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test',
                           'plural': 'assemblies', 'name': ASM_NAME}
    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Are you sure you want to teardown {ASM_NAME} [y/N]: y
"""


def test_cli_assembly_teardown_with_not_found_exception(mocker):
    # mock Kubernetes delete API to raise a not found exception
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.delete_namespaced_custom_object.side_effect = raise_not_found
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME], input='y')

    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Are you sure you want to teardown {ASM_NAME} [y/N]: y
Ignoring teardown, {ASM_NAME} not found
"""


def test_cli_assembly_teardown_with_force_and_wait(mocker):
    # mock Kubernetes delete API to do nothing and the get api to raise a not found exception
    # i.e that the deleted assembly no longer exists
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.delete_namespaced_custom_object.return_value = {}
    instance.get_namespaced_custom_object.side_effect = raise_not_found
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'teardown', '--name', ASM_NAME, '--force', '--wait'])

    assert result.exit_code == 0
    assert result.output == f"""Tearing down assembly {ASM_NAME}
Waiting for assembly to be torn down
"""


def test_cli_assembly_list_if_assembly_deployed(mocker):
    # mock the Kubernetes function to return TEST_ASSEMBLY
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.list_namespaced_custom_object.return_value = {'items': [build_assembly_object(ASM_NAME, True)]}

    result = TEST_CLI.invoke(main.cli, ['assembly', 'list'])

    assert result.exit_code == 0
    assert result.output == f"""ASSEMBLY NAME  NAMESPACE
{ASM_NAME}       {TEST_NS}
"""


def test_cli_assembly_list_error_response(mocker):
    mock = mocker.patch('kxicli.commands.assembly._list_assemblies', mocked_return_false)
    result = TEST_CLI.invoke(main.cli, ['assembly', 'list'])
    assert result.exit_code == 1


def test_cli_assembly_create_from_file(mocker):
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)
    mock_create_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)

    result = TEST_CLI.invoke(main.cli, ['assembly', 'create', '--filepath', test_asm_file])

    assert result.exit_code == 0
    assert result.output == f"""Using assembly.filepath from command line option: {test_asm_file}
Submitting assembly from {test_asm_file}
Custom assembly resource basic-assembly created!
"""
    current_ns = appended_args[0]['namespace']
    assert appended_args == [
        {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': current_ns, 'plural': 'assemblies',
         'body': assembly._add_last_applied_configuration_annotation(test_asm)}]


def test_cli_assembly_create_with_context_not_set(mocker):
    # When context is not set, the default namespace is taken from cli-config
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)
    mock_create_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
    mocker.patch('kubernetes.config.list_kube_config_contexts', mocked_k8s_list_empty_config)

    result = TEST_CLI.invoke(main.cli, ['assembly', 'create', '--filepath', test_asm_file])

    assert result.exit_code == 0
    assert result.output == f"""Using namespace from config file {common.config.config_file}: test
Using assembly.filepath from command line option: {test_asm_file}
Submitting assembly from {test_asm_file}
Custom assembly resource basic-assembly created!
"""
    assert appended_args == [
        {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': 'test',
         'plural': 'assemblies', 'body': assembly._add_last_applied_configuration_annotation(test_asm)}]


def test_cli_assembly_create_and_wait(mocker):
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)
    mock_instance = mocker.patch(CUSTOM_OBJECT_API).return_value
    mock_create_assemblies(mock_instance)
    mock_instance.get_namespaced_custom_object.return_value = build_assembly_object(ASM_NAME, True)

    result = TEST_CLI.invoke(main.cli, ['assembly', 'create', '--filepath', test_asm_file, '--wait'])

    assert result.exit_code == 0
    assert result.output == f"""Using assembly.filepath from command line option: {test_asm_file}
Submitting assembly from {test_asm_file}
Waiting for assembly to enter "Ready" state
Custom assembly resource basic-assembly created!
"""
    current_ns = appended_args[0]['namespace']
    assert appended_args == [
        {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': current_ns, 'plural': 'assemblies',
         'body': assembly._add_last_applied_configuration_annotation(test_asm)}]


def test_cli_assembly_create_without_filepath(mocker):
    mocker.patch('kxicli.common.is_interactive_session', return_false)
    result = TEST_CLI.invoke(main.cli, ['assembly', 'create'])
    assert result.exit_code == 1
    assert result.output == f'Error: Could not find expected option. Please set command line argument --filepath or configuration value assembly.filepath in config file {common.config.config_file}\n'


def test_cli_assembly_create_without_filepath_interactive_session(mocker):
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)
    mock_create_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
    mocker.patch('kxicli.common.is_interactive_session', return_true)

    result = TEST_CLI.invoke(main.cli, ['assembly', 'create'], input=test_asm_file)

    assert result.exit_code == 0
    assert result.output == f"""Please enter a path to the assembly file: {test_asm_file}
Submitting assembly from {test_asm_file}
Custom assembly resource basic-assembly created!
"""
    current_ns = appended_args[0]['namespace']
    assert appended_args == [
        {'group': assembly.API_GROUP, 'version': PREFERRED_VERSION, 'namespace': current_ns, 'plural': 'assemblies',
         'body': assembly._add_last_applied_configuration_annotation(test_asm)}]


def test_cli_assembly_backup_assemblies(mocker):
    mock_list_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)

    with temp_asm_file() as test_asm_list_file:
        result = TEST_CLI.invoke(main.cli, ['assembly', 'backup', '--filepath', test_asm_list_file])

        assert result.exit_code == 0
        assert result.output == f"""warn=Refusing to backup assemblies: ['{ASM_NAME3}']. These assemblies are missing 'kubectl.kubernetes.io/last-applied-configuration' annotation. Please restart these assemblies manually.
Persisted assembly definitions for ['{ASM_NAME}', '{ASM_NAME2}'] to {test_asm_list_file}
"""
        with open(test_asm_list_file, 'rb') as f:
            expect = yaml.full_load(f)
            assert expect == ASSEMBLY_BACKUP_LIST


def test_cli_assembly_backup_assemblies_overwrites_when_file_already_exists(mocker):
    mock_list_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
    with temp_asm_file() as test_asm_list_file:
        with open(test_asm_list_file, 'w') as f:
            f.write('a test file')

        # Respond 'y' to the prompt to overwrite
        result = TEST_CLI.invoke(main.cli, ['assembly', 'backup', '--filepath', test_asm_list_file], input='y')

        assert result.exit_code == 0
        assert result.output == f"""
{test_asm_list_file} file exists. Do you want to overwrite it with a new assembly backup file? [y/N]: y
warn=Refusing to backup assemblies: ['{ASM_NAME3}']. These assemblies are missing 'kubectl.kubernetes.io/last-applied-configuration' annotation. Please restart these assemblies manually.
Persisted assembly definitions for ['{ASM_NAME}', '{ASM_NAME2}'] to {test_asm_list_file}
"""
        with open(test_asm_list_file, 'rb') as f:
            assert yaml.full_load(f) == ASSEMBLY_BACKUP_LIST


def test_cli_assembly_backup_assemblies_creates_new_when_file_already_exists(mocker):
    mock_list_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
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


def test_cli_assembly_backup_assemblies_forces_overwrite_when_file_already_exists(mocker):
    mock_list_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
    with temp_asm_file() as test_asm_list_file:
        with open(test_asm_list_file, 'w') as f:
            f.write('yet another test file')

        result = TEST_CLI.invoke(main.cli, ['assembly', 'backup', '--filepath', test_asm_list_file, '--force'])

        assert result.exit_code == 0
        assert result.output == f"""warn=Refusing to backup assemblies: ['{ASM_NAME3}']. These assemblies are missing 'kubectl.kubernetes.io/last-applied-configuration' annotation. Please restart these assemblies manually.
Persisted assembly definitions for ['{ASM_NAME}', '{ASM_NAME2}'] to {test_asm_list_file}
"""
        with open(test_asm_list_file, 'rb') as f:
            assert yaml.full_load(f) == ASSEMBLY_BACKUP_LIST
