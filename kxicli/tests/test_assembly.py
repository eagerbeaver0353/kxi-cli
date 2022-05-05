import copy
import json
from xml.dom import NOT_FOUND_ERR
from click.testing import CliRunner
import kubernetes as k8s
from kxicli import main
from kxicli.commands import assembly

ASM_NAME = 'test_asm'
TEST_CLI = CliRunner()
CUSTOM_OBJECT_API = 'kubernetes.client.CustomObjectsApi'
PREFERRED_VERSION_FUNC = 'kxicli.commands.assembly.get_preferred_api_version'
PREFERRED_VERSION = 'v1'

TEST_ASSEMBLY = {
        'metadata': {
            'name': ASM_NAME
        },
        'status': {
            'conditions': [
                {
                    'type': 'AssemblyReady',
                    'status': 'True'
                }
            ]
        }
    }

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
    assert assembly._format_assembly_status(TEST_ASSEMBLY) == formatted_status

def test_format_assembly_status_with_message_and_reason():
    asm = copy.deepcopy(TEST_ASSEMBLY)
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
    instance.get_namespaced_custom_object.return_value = TEST_ASSEMBLY
    assert assembly._assembly_status(namespace='test_ns', name='test_asm')

def test_status_with_false_status(mocker):
    # set False status
    asm = copy.deepcopy(TEST_ASSEMBLY)
    asm['status']['conditions'][0]['status'] = 'False'

    # mock the Kubernetes function to return asm above
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = asm

    assert assembly._assembly_status(namespace='test_ns', name='test_asm', print_status=True) == False

def test_create_with_false_status(mocker):
    # set False status
    asm = copy.deepcopy(TEST_ASSEMBLY)
    asm['status']['conditions'][0]['status'] = 'False'

    # mock the Kubernetes function to return asm above
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = asm

    assert assembly._assembly_status(namespace='test_ns', name='test_asm', print_status=True) == False

# CLI invoked tests

def test_cli_assembly_status_if_assembly_not_deployed(mocker):
    # mock the Kubernetes function to return an empty assembly
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = {}

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', 'test_asm'])
    assert result.output == 'Assembly not yet deployed\n'
    assert result.exit_code == 1

def test_cli_assembly_status_if_assembly_deployed(mocker):
    # mock the Kubernetes function to return TEST_ASSEMBLY
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = TEST_ASSEMBLY

    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', 'test_asm'])

    assert result.exit_code == 0
    assert result.output == f'{json.dumps(TRUE_STATUS, indent=2)}\n'

def test_cli_assembly_status_with_false_status(mocker):
    # set False status
    asm = copy.deepcopy(TEST_ASSEMBLY)
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
    assert result.output == f'Assembly {ASM_NAME} not found\n'

def test_cli_assembly_status_with_wait_for_ready(mocker):
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.get_namespaced_custom_object.return_value = TEST_ASSEMBLY

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'status', '--name', ASM_NAME, '--wait-for-ready'])

    assert result.exit_code == 0
    assert result.output == f"""Waiting for assembly to enter "Ready" state
{json.dumps(TRUE_STATUS, indent=2)}\n"""

def test_cli_assembly_delete_without_confirm():
    # answer 'n' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'delete', '--name', ASM_NAME], input='n')

    assert result.exit_code == 0
    assert result.output == f"""Deleting assembly {ASM_NAME}
Are you sure you want to delete {ASM_NAME} [y/N]: n
Not deleting assembly {ASM_NAME}\n"""

def test_cli_assembly_delete_with_confirm(mocker):
    # mock Kubernetes delete API to do nothing
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.delete_namespaced_custom_object.return_value = {}
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'delete', '--name', ASM_NAME], input='y')

    assert result.exit_code == 0
    assert result.output == f"""Deleting assembly {ASM_NAME}
Are you sure you want to delete {ASM_NAME} [y/N]: y
"""

def test_cli_assembly_delete_with_not_found_exception(mocker):
    # mock Kubernetes delete API to raise a not found exception
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.delete_namespaced_custom_object.side_effect = raise_not_found
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'delete', '--name', ASM_NAME], input='y')

    assert result.exit_code == 0
    assert result.output == f"""Deleting assembly {ASM_NAME}
Are you sure you want to delete {ASM_NAME} [y/N]: y
Ignoring delete, {ASM_NAME} not found
"""

def test_cli_assembly_delete_with_force_and_wait(mocker):
    # mock Kubernetes delete API to do nothing and the get api to raise a not found exception
    # i.e that the deleted assembly no longer exists
    mock = mocker.patch(CUSTOM_OBJECT_API)
    instance = mock.return_value
    instance.delete_namespaced_custom_object.return_value = {}
    instance.get_namespaced_custom_object.side_effect = raise_not_found
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)

    # answer 'y' to the prompt asking to confirm you want to delete the assembly
    result = TEST_CLI.invoke(main.cli, ['assembly', 'delete', '--name', ASM_NAME, '--force', '--wait'])

    assert result.exit_code == 0
    assert result.output == f"""Deleting assembly {ASM_NAME}
Waiting for assembly to be deleted
"""
