import os
import typing
import yaml
from pathlib import Path

from click import BaseCommand
from click.testing import CliRunner
from functools import partial
from pytest_mock import MockerFixture
from subprocess import CompletedProcess
from typing import List, Optional

from kxicli import config
from kxicli import main
from kxicli.commands.azure import default_insights_namespace, default_insights_release
from kxicli.common import get_default_val
from test_azure import fake_version, fake_values_yaml, helm_version_checked, fake_chart_repo_url, read_secret
from utils import temp_file, mock_helm_env, mock_kube_crd_api, mock_kube_secret_api, mock_validate_secret, \
    fake_docker_config_yaml, raise_not_found, return_none, return_true
from test_install_e2e import mock_copy_secret, mocked_crd_exists, mocked_create_crd, mocked_delete_crd, mocked_installed_chart_json, \
    mocked_installed_operator_versions, mock_get_operator_version, test_operator_helm_name, mock__delete_assembly, DELETE_ASSEMBLIES_FUNC
from test_assembly import ASSEMBLY_BACKUP_LIST, CUSTOM_OBJECT_API, mock_list_assemblies
from test_helm import fun_subprocess_run

a_test_asm_str: str = 'a test asm file'
default_config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')
default_config: str = 'default'
default_env: dict = {
    'KUBECONFIG': str(Path(__file__).parent / 'files' / 'test-kube-config')
}

config.config_file = default_config_file
config.load_config(default_config)

# config must be loaded before get_default_val
default_assembly_backup_file: str = get_default_val('assembly.backup.file')

# fun names
fun_get_helm_version_checked: str = 'kxicli.resources.helm.get_helm_version_checked'
fun_assembly_create_assemblies_from_file: str = 'kxicli.commands.assembly.create_assemblies_from_file'
fun_install_create_namespace: str = 'kxicli.resources.helm.create_namespace'
fun_click_confirm: str = 'click.confirm'
fun_common_get_existing_crds: str = 'kxicli.common.get_existing_crds'
fun_common_delete_crd: str = 'kxicli.common.delete_crd'
fun_install_operator_versions: str = 'kxicli.commands.install.get_installed_operator_versions'
fun_install_insights_installed: str = 'kxicli.commands.install.insights_installed'
fun_assembly_delete_running_assemblies: str = 'kxicli.commands.assembly.delete_running_assemblies'
fun_assembly_backup_assemblies: str = 'kxicli.commands.assembly.backup_assemblies'
fun_assembly_get_assemblies_list: str = 'kxicli.commands.assembly.get_assemblies_list'

config_json_file_name: str = 'config.json'
fake_assemblies: List[str] = ['asdf']

class FakeK8SCustomResource:
    @staticmethod
    def get(key: str) -> List[str]:
        return fake_assemblies

# Mocks

def common_delete_crd(crd):
    """tst"""
    pass


def get_helm_version_checked():
    return helm_version_checked


def return_true_list(*args, **kwargs):
    return [True]


def mocked_create_assemblies_from_file_exists(namespace, filepath, use_kubeconfig, wait=None):
    global mocked_assembly_res
    mocked_assembly_res['filepath'] = filepath
    with open(filepath, 'r') as af:
        mocked_assembly_res['asm_file_content'] = af.read()


def mocked_backup_assemblies(namespace: str, filepath: str, force: bool):
    return filepath


def mocked_get_assemblies_list(namespace: str) -> FakeK8SCustomResource:
    return FakeK8SCustomResource()


def subprocess_run_helm_success_install_append_res(
        *popenargs, res: list = [], **kwargs
):
    env: dict = kwargs.get('env')
    res_item: dict = {}
    res_item['env'] = env
    res_item['cmd'] = popenargs[0]
    try:
        res_item['DOCKER_CONFIG'] = env['DOCKER_CONFIG']
        with open(str(Path(env['DOCKER_CONFIG']) / config_json_file_name)) as dc:
            res_item['dockerconfigjson'] = dc.read()
    except BaseException as e:
        print(f'Cant read dockerconfigjson: {e}')
        pass
    res.append(res_item)
    return CompletedProcess(args=popenargs[0], returncode=0, stdout='', stderr='')


def click_confirm_yes(
        text: str,
        default: Optional[bool] = False,
        abort: bool = False,
        prompt_suffix: str = ": ",
        show_default: bool = True,
        err: bool = False,
) -> bool:
    return True


def common_get_existing_crds(crds: List[str]) -> List[str]:
    return crds


# Tests

def test_assembly_restore(mocker: MockerFixture):
    mocker.patch(fun_assembly_create_assemblies_from_file, return_true_list)

    runner = CliRunner()
    with temp_file(default_assembly_backup_file) as asm_file:
        with open(asm_file, mode='w') as f:
            f.write(a_test_asm_str)
        result = runner.invoke(
            typing.cast(BaseCommand, main.cli),
            args=[
                'azure',
                'assembly',
                'restore',
                '--namespace', default_insights_namespace,
                '--assembly-backup-filepath', asm_file
            ],
            env=default_env
        )
        assert result.exit_code == 0


def test_assembly_delete(mocker: MockerFixture):
    delete_assembly_args = []
    mock_list_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, partial(mock__delete_assembly, delete_assembly_args=delete_assembly_args))

    runner = CliRunner()
    result = runner.invoke(
        typing.cast(BaseCommand, main.cli),
        args=[
            'azure',
            'assembly',
            'delete',
            '--force'
        ],
        env=default_env
    )
    assert result.exit_code == 0
    assert delete_assembly_args == [
        {'name': 'test_asm',  'namespace': 'test'},
        {'name': 'test_asm2', 'namespace': 'test'},
        {'name': 'test_asm3', 'namespace': 'test'}
    ]



def test_assembly_backup(mocker: MockerFixture):
    mock_list_assemblies(mocker.patch(CUSTOM_OBJECT_API).return_value)
    runner = CliRunner()
    with temp_file(get_default_val('assembly.backup.file')) as asm_file:
        result = runner.invoke(typing.cast(BaseCommand, main.cli), 
                               ['azure', 'assembly', 'backup', 
                                '--namespace', default_insights_namespace,
                                '--assembly-backup-filepath', asm_file
                                ]
                            )
        assert result.exit_code == 0
        with open(asm_file, 'rb') as f:
            expect = yaml.full_load(f)
            assert expect == ASSEMBLY_BACKUP_LIST
        

def test_backup_assemblies_none(mocker: MockerFixture):
    mock_instance = mocker.patch(CUSTOM_OBJECT_API).return_value
    mock_instance.list_namespaced_custom_object.return_value = {'items': []}
    runner = CliRunner()
    with temp_file(get_default_val('assembly.backup.file')) as asm_file:
        result = runner.invoke(typing.cast(BaseCommand, main.cli), 
                               ['azure', 'assembly', 'backup', 
                                '--namespace', default_insights_namespace,
                                '--assembly-backup-filepath', asm_file
                                ]
                            )
        assert result.exit_code == 0
        assert not os.path.isfile(asm_file)


def test_install(mocker: MockerFixture):
    global subprocess_params
    subprocess_params = []

    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_append_res, res=subprocess_params)
    mock_kube_secret_api(mocker, read=read_secret)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    mocker.patch(fun_install_create_namespace, return_none)
    mocker.patch(fun_get_helm_version_checked, get_helm_version_checked)
    mocker.patch(fun_assembly_create_assemblies_from_file, return_true_list)
    mocker.patch('kxicli.commands.install.get_installed_charts', lambda *args: [])
    mocker.patch(fun_install_operator_versions, lambda *args: ([], []))
    mock_validate_secret(mocker)
    mock_get_operator_version(mocker)
    mock_copy_secret(mocker)

    runner = CliRunner()
    with temp_file(file_name='values.yaml') as values_file:
        values_file_name = values_file
        with open(values_file, mode='w') as vf:
            vf.write(fake_values_yaml)
        actual_res = runner.invoke(
            typing.cast(BaseCommand, main.cli),
            args=[
                'azure',
                'install',
                '--version', fake_version,
                '--operator-version', fake_version,
                '--filepath', values_file,
                '--force'
            ],
            env=default_env
        )
    assert actual_res.exit_code == 0
    assert len(subprocess_params) == 2
    operator_install = subprocess_params[0]
    insights_install = subprocess_params[1]
    assert 'DOCKER_CONFIG' in dict(insights_install['env'])
    assert insights_install['dockerconfigjson'] == fake_docker_config_yaml
    assert operator_install['dockerconfigjson'] == fake_docker_config_yaml
    assert operator_install['cmd'] == [
                'helm', 'upgrade', '--install', '-f', values_file_name, default_insights_release, f'{fake_chart_repo_url}/kxi-operator',
                '--version', fake_version,
                '--namespace', 'kxi-operator'
            ]
    assert insights_install['cmd'] == [
                'helm', 'upgrade', '--install', '-f', values_file_name, default_insights_release, f'{fake_chart_repo_url}/insights',
                '--set', 'keycloak.importUsers=true',
                '--version', fake_version,
                '--namespace', 'test'
            ]


def test_uninstall(mocker: MockerFixture):
    global subprocess_params
    subprocess_params = []

    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_append_res, res=subprocess_params)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    mocker.patch(fun_assembly_get_assemblies_list, mocked_get_assemblies_list)
    mocker.patch(fun_common_get_existing_crds, common_get_existing_crds)
    mocker.patch(fun_common_delete_crd, common_delete_crd)
    mocker.patch(fun_install_insights_installed, return_true)
    mocker.patch(fun_assembly_backup_assemblies, mocked_backup_assemblies)
    mocker.patch(fun_assembly_delete_running_assemblies, return_true_list)
    mocker.patch(fun_get_helm_version_checked, get_helm_version_checked)
    mocker.patch(fun_install_operator_versions, mocked_installed_operator_versions)


    runner = CliRunner()
    with temp_file(default_assembly_backup_file) as asm_file:
        with open(asm_file, mode='w') as f:
            f.write(a_test_asm_str)
        result = runner.invoke(
            typing.cast(BaseCommand, main.cli),
            args=[
                'azure',
                'uninstall',
                '--assembly-backup-filepath', asm_file,
                '--force'
            ],
            env=default_env
        )
    assert result.exit_code == 0
    assert len(subprocess_params) == 2
    insights_uninstall = subprocess_params[0]
    operator_uninstall = subprocess_params[1]
    
    assert insights_uninstall['cmd'] == ['helm', 'uninstall', default_insights_release, '--namespace', 'test']
    assert operator_uninstall['cmd'] == ['helm', 'uninstall', 'test-op-helm', '--namespace', 'kxi-operator']
    

def test_upgrade(mocker: MockerFixture):
    global subprocess_params
    subprocess_params = []

    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_append_res, res=subprocess_params)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    mock_kube_secret_api(mocker, read=read_secret)
    mocker.patch(fun_install_create_namespace, return_none)
    mocker.patch(fun_get_helm_version_checked, get_helm_version_checked)
    mocker.patch(fun_assembly_create_assemblies_from_file, return_true_list)
    mocker.patch(fun_assembly_get_assemblies_list, mocked_get_assemblies_list)
    mocker.patch(fun_common_get_existing_crds, common_get_existing_crds)
    mocker.patch(fun_common_delete_crd, common_delete_crd)
    mocker.patch(fun_install_insights_installed, return_true)
    mocker.patch(fun_assembly_backup_assemblies, mocked_backup_assemblies)
    mocker.patch(fun_assembly_delete_running_assemblies, return_true_list)
    mocker.patch('kxicli.commands.install.get_installed_charts', mocked_installed_chart_json)
    mocker.patch(fun_install_operator_versions, mocked_installed_operator_versions)
    mocker.patch('kxicli.common.crd_exists', mocked_crd_exists)
    mock_validate_secret(mocker)
    mock_get_operator_version(mocker)
    mock_copy_secret(mocker)
    mock_helm_env(mocker)
    mock_kube_crd_api(mocker, create=mocked_create_crd, delete=mocked_delete_crd)

    runner = CliRunner()
    with temp_file(default_assembly_backup_file) as asm_file:
        with open(asm_file, mode='w') as f:
            f.write(a_test_asm_str)
        with temp_file(file_name='values.yaml') as values_file:
            with open(values_file, mode='w') as vf:
                vf.write(fake_values_yaml)
            values_file_name = values_file
            result = runner.invoke(
                typing.cast(BaseCommand, main.cli),
                args=[
                    'azure',
                    'upgrade',
                    '--version', fake_version,
                    '--operator-version', fake_version,
                    '--assembly-backup-filepath', asm_file,
                    '--filepath', values_file,
                    '--force'
                ],
                env=default_env
            )
    assert result.exit_code == 0
    assert len(subprocess_params) == 3
    helm_fetch = subprocess_params[0]
    operator_install = subprocess_params[1]
    insights_install = subprocess_params[2]
    assert 'DOCKER_CONFIG' in dict(insights_install['env'])
    assert insights_install['dockerconfigjson'] == fake_docker_config_yaml
    assert operator_install['dockerconfigjson'] == fake_docker_config_yaml
    
    assert helm_fetch['cmd'] == ['helm', 'fetch', f'{fake_chart_repo_url}/kxi-operator',
        '--destination', os.getcwd() + '/tests/files/helm',
        '--version', fake_version
        ]
    assert operator_install['cmd'] == [
                'helm', 'upgrade', '--install', '-f', values_file_name, test_operator_helm_name, f'{fake_chart_repo_url}/kxi-operator',
                '--version', fake_version,
                '--namespace', 'kxi-operator'
            ]
    assert insights_install['cmd'] == [
                'helm', 'upgrade', '--install', '-f', values_file_name, default_insights_release, f'{fake_chart_repo_url}/insights',
                '--version', fake_version,
                '--namespace', 'test'
            ]

def test_upgrade_with_no_assemblies_running(mocker: MockerFixture):
    global subprocess_params
    subprocess_params = []

    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_append_res, res=subprocess_params)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    mock_kube_secret_api(mocker, read=read_secret)
    mocker.patch(fun_install_create_namespace, return_none)
    mocker.patch(fun_get_helm_version_checked, get_helm_version_checked)
    mocker.patch(fun_assembly_create_assemblies_from_file, return_true_list)
    mocker.patch(fun_assembly_get_assemblies_list, raise_not_found)
    mocker.patch(fun_common_get_existing_crds, common_get_existing_crds)
    mocker.patch(fun_common_delete_crd, common_delete_crd)
    mocker.patch(fun_install_insights_installed, return_true)
    mocker.patch(fun_assembly_backup_assemblies, return_none)
    mocker.patch(fun_assembly_delete_running_assemblies, return_true_list)
    mocker.patch('kxicli.commands.install.get_installed_charts', mocked_installed_chart_json)
    mocker.patch(fun_install_operator_versions, mocked_installed_operator_versions)
    mocker.patch('kxicli.common.crd_exists', mocked_crd_exists)
    mock_validate_secret(mocker)
    mock_get_operator_version(mocker)
    mock_copy_secret(mocker)
    mock_helm_env(mocker)
    mock_kube_crd_api(mocker, create=mocked_create_crd, delete=mocked_delete_crd)

    runner = CliRunner()
    with temp_file(file_name='values.yaml') as values_file:
        with open(values_file, mode='w') as vf:
            vf.write(fake_values_yaml)
        values_file_name = values_file
        result = runner.invoke(
            typing.cast(BaseCommand, main.cli),
            args=[
                'azure',
                'upgrade',
                '--version', fake_version,
                '--operator-version', fake_version,
                '--filepath', values_file,
                '--force'
            ],
            env=default_env
        )
    assert result.exit_code == 0
    assert len(subprocess_params) == 3
    helm_fetch = subprocess_params[0]
    operator_install = subprocess_params[1]
    insights_install = subprocess_params[2]
    assert 'DOCKER_CONFIG' in dict(insights_install['env'])
    assert insights_install['dockerconfigjson'] == fake_docker_config_yaml
    assert operator_install['dockerconfigjson'] == fake_docker_config_yaml

    assert helm_fetch['cmd'] == ['helm', 'fetch', f'{fake_chart_repo_url}/kxi-operator',
        '--destination', os.getcwd() + '/tests/files/helm',
        '--version', fake_version
        ]
    assert operator_install['cmd'] == [
                'helm', 'upgrade', '--install', '-f', values_file_name, test_operator_helm_name, f'{fake_chart_repo_url}/kxi-operator',
                '--version', fake_version,
                '--namespace', 'kxi-operator'
            ]
    assert insights_install['cmd'] == [
                'helm', 'upgrade', '--install', '-f', values_file_name, default_insights_release, f'{fake_chart_repo_url}/insights',
                '--version', fake_version,
                '--namespace', 'test'
            ]

def test_restore_assemblies_exists(mocker: MockerFixture):
    asm_file_content: str = 'a test asm file'
    global mocked_assembly_res
    mocked_assembly_res = {}

    mocker.patch(fun_assembly_create_assemblies_from_file, mocked_create_assemblies_from_file_exists)
    mocker.patch(fun_click_confirm, click_confirm_yes)
    runner = CliRunner()
    with temp_file(get_default_val('assembly.backup.file')) as asm_file:
        with open(asm_file, mode='w') as f:
            f.write(asm_file_content)
        runner.invoke(typing.cast(BaseCommand, main.cli), 
                               ['azure', 'assembly', 'restore', 
                                '--namespace', default_insights_namespace,
                                '--assembly-backup-filepath', asm_file
                                ]
                            )

        assert asm_file == mocked_assembly_res['filepath']
    assert asm_file_content == mocked_assembly_res['asm_file_content']

def test_restore_assemblies_not_exists(mocker: MockerFixture):
    mocker.patch('kxicli.commands.assembly._create_assembly', return_true)
    mocker.patch(fun_click_confirm, click_confirm_yes)
    runner = CliRunner()
    with temp_file(get_default_val('assembly.backup.file')) as asm_file:
        result = runner.invoke(typing.cast(BaseCommand, main.cli), 
                            ['azure', 'assembly', 'restore', 
                            '--namespace', default_insights_namespace,
                            '--assembly-backup-filepath', asm_file
                            ]
                        )
    assert result.exit_code == 1
    assert result.output == f'Error: File not found: {asm_file}\n'
