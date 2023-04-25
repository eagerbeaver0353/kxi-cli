import os
import typing
import yaml
from pathlib import Path

from click import BaseCommand
from click.testing import CliRunner
from functools import partial
from pytest_mock import MockerFixture
from subprocess import CompletedProcess
from typing import List

from kxicli import config
from kxicli import main
from kxicli.common import get_default_val
import utils
from test_install_e2e import mock_copy_secret, mocked_crd_exists, mocked_create_crd, mocked_delete_crd, mocked_installed_chart_json, \
    mocked_installed_operator_versions, mock_get_operator_version, test_operator_helm_name, mocked_read_secret, mocked_helm_version_checked
from test_helm import fun_subprocess_run
from test_install_e2e import mock_read_cached_crd_data

a_test_asm_str: str = 'a test asm file'
default_config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')
default_config: str = 'default'
default_env: dict = {
    'KUBECONFIG': str(Path(__file__).parent / 'files' / 'test-kube-config')
}
default_insights_namespace: str = 'insights'
default_insights_release: str = 'insights'
default_docker_config_secret_name: str = 'kxi-acr-pull-secret'
fake_chart_repo: str = 'kxinsightsprod.azurecr.io'
fake_chart_repo_url: str = f'oci://{fake_chart_repo}'
fake_version: str = '1.2.3'
fake_values: dict = {
    'global': {
        'image': {
            'repository': f'{fake_chart_repo}/images/kx-insights'
        },
        'imagePullSecrets': [
            {
                'name': f'{default_docker_config_secret_name}'
            }
        ]
    }
}
fake_values_yaml: str = yaml.dump(fake_values)

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


def return_true_list(*args, **kwargs):
    return [True]


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


def common_get_existing_crds(crds: List[str]) -> List[str]:
    return crds


def install_mocks(mocker):
    mocker.patch(fun_install_create_namespace, utils.return_none)
    mocker.patch(fun_assembly_create_assemblies_from_file, return_true_list)
    utils.mock_validate_secret(mocker)
    utils.mock_kube_secret_api(mocker, read=partial(mocked_read_secret, image_pull_secret_name=default_docker_config_secret_name))
    mock_get_operator_version(mocker)
    mock_copy_secret(mocker)

def uninstall_mocks(mocker):
    mocker.patch(fun_assembly_get_assemblies_list, mocked_get_assemblies_list)
    mocker.patch(fun_common_get_existing_crds, common_get_existing_crds)
    mocker.patch(fun_common_delete_crd, common_delete_crd)
    mocker.patch(fun_install_insights_installed, utils.return_true)
    mocker.patch(fun_assembly_backup_assemblies, mocked_backup_assemblies)
    mocker.patch(fun_assembly_delete_running_assemblies, return_true_list)
    mocker.patch(fun_install_operator_versions, mocked_installed_operator_versions)

def upgrade_mocks(mocker):
    install_mocks(mocker)
    uninstall_mocks(mocker)
    utils.mock_helm_get_values(mocker, fake_values)
    utils.mock_helm_env(mocker)
    utils.mock_kube_crd_api(mocker, create=mocked_create_crd, delete=mocked_delete_crd)
    mocker.patch(fun_get_helm_version_checked, mocked_helm_version_checked)
    mocker.patch('kxicli.commands.install.get_installed_charts', mocked_installed_chart_json)
    mocker.patch('kxicli.common.crd_exists', mocked_crd_exists)
    mocker.patch('kxicli.commands.install.read_cached_crd_files', mock_read_cached_crd_data)

def upgrade_checks(result, values_file_name='values.yaml', chart_repo_url=fake_chart_repo_url):
    assert result.exit_code == 0
    assert len(subprocess_params) == 3
    helm_fetch = subprocess_params[0]
    operator_install = subprocess_params[1]
    insights_install = subprocess_params[2]
    assert 'DOCKER_CONFIG' in dict(insights_install['env'])
    assert insights_install['dockerconfigjson'] == utils.fake_docker_config_yaml
    assert operator_install['dockerconfigjson'] == utils.fake_docker_config_yaml

    assert helm_fetch['cmd'] == ['helm', 'fetch', f'{chart_repo_url}/kxi-operator',
        '--destination', os.getcwd() + '/tests/files/helm',
        '--version', fake_version
        ]
    assert operator_install['cmd'] == [
                'helm', 'upgrade', '--install', '--version', fake_version, '-f', values_file_name, test_operator_helm_name, f'{chart_repo_url}/kxi-operator',
                '--namespace', 'kxi-operator'
            ]
    assert insights_install['cmd'] == [
                'helm', 'upgrade', '--install', '--version', fake_version, '-f', values_file_name, default_insights_release, f'{chart_repo_url}/insights',
                '--set', 'keycloak.importUsers=false', '--namespace', utils.namespace()
            ]

# Tests

def test_install(mocker: MockerFixture):
    global subprocess_params
    subprocess_params = []
    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_append_res, res=subprocess_params)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    mocker.patch(fun_get_helm_version_checked, mocked_helm_version_checked)
    mocker.patch('kxicli.commands.install.get_installed_charts', lambda *args: [])
    mocker.patch(fun_install_operator_versions, lambda *args: ([], []))
    install_mocks(mocker)

    runner = CliRunner()
    with utils.temp_file(file_name='values.yaml') as values_file:
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
    assert insights_install['dockerconfigjson'] == utils.fake_docker_config_yaml
    assert operator_install['dockerconfigjson'] == utils.fake_docker_config_yaml
    assert operator_install['cmd'] == [
                'helm', 'upgrade', '--install', '--version', fake_version, '-f', values_file_name, default_insights_release, f'{fake_chart_repo_url}/kxi-operator',
                '--namespace', 'kxi-operator'
            ]
    assert insights_install['cmd'] == [
                'helm', 'upgrade', '--install', '--version', fake_version, '-f', values_file_name, default_insights_release, f'{fake_chart_repo_url}/insights',
                '--set', 'keycloak.importUsers=true',
                '--namespace', utils.namespace()
            ]


def test_uninstall(mocker: MockerFixture):
    global subprocess_params
    subprocess_params = []
    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_append_res, res=subprocess_params)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    mocker.patch(fun_get_helm_version_checked, mocked_helm_version_checked)
    uninstall_mocks(mocker)

    runner = CliRunner()
    with utils.temp_file(default_assembly_backup_file) as asm_file:
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

    assert insights_uninstall['cmd'] == ['helm', 'uninstall', default_insights_release, '--namespace', utils.namespace()]
    assert operator_uninstall['cmd'] == ['helm', 'uninstall', 'test-op-helm', '--namespace', 'kxi-operator']


def test_upgrade(mocker: MockerFixture):
    global subprocess_params
    subprocess_params = []
    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_append_res, res=subprocess_params)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    upgrade_mocks(mocker)
    
    runner = CliRunner()
    with utils.temp_file(default_assembly_backup_file) as asm_file:
        with open(asm_file, mode='w') as f:
            f.write(a_test_asm_str)
        with utils.temp_file(file_name='values.yaml') as values_file:
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
    upgrade_checks(result, values_file_name)

def test_upgrade_with_no_assemblies_running(mocker: MockerFixture):
    global subprocess_params
    subprocess_params = []
    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_append_res, res=subprocess_params)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    upgrade_mocks(mocker)

    runner = CliRunner()
    with utils.temp_file(file_name='values.yaml') as values_file:
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
    upgrade_checks(result, values_file_name)


def test_upgrade_with_chart_repo_url(mocker: MockerFixture):
    global subprocess_params
    subprocess_params = []
    test_chart_repo_url = 'oci://test_chart_repo_url'
    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_append_res, res=subprocess_params)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    upgrade_mocks(mocker)

    runner = CliRunner()
    with utils.temp_file(default_assembly_backup_file) as asm_file:
        with open(asm_file, mode='w') as f:
            f.write(a_test_asm_str)
        with utils.temp_file(file_name='values.yaml') as values_file:
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
                    '--chart-repo-url', test_chart_repo_url,
                    '--force'
                ],
                env=default_env
            )
    upgrade_checks(result, values_file_name, chart_repo_url=test_chart_repo_url)

def test_upgrade_without_filepath(mocker: MockerFixture):
    global subprocess_params
    subprocess_params = []
    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_append_res, res=subprocess_params)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    upgrade_mocks(mocker)

    runner = CliRunner()
    result = runner.invoke(
        typing.cast(BaseCommand, main.cli),
        args=[
            'azure',
            'upgrade',
            '--version', fake_version,
            '--operator-version', fake_version,
            '--force'
        ],
        env=default_env
    )
    upgrade_checks(result, values_file_name='-')