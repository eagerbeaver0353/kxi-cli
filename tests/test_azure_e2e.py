import os
import typing
import pyk8s
import yaml
from pathlib import Path

from click import BaseCommand
from click.testing import CliRunner
from dataclasses import dataclass
from functools import partial
from pytest_mock import MockerFixture
from typing import List, Optional

from kxicli import config
from kxicli import main
from kxicli.common import get_default_val
import mocks
import utils
from test_install_e2e import mock_copy_secret, mock_delete_crd, mocked_installed_operator_versions,\
    mock_get_operator_version, test_operator_helm_name, mocked_read_secret, mocked_helm_version_checked,\
    mock_read_cached_crd_data, mock_subprocess_run, install_upgrade_checks, \
    check_subprocess_run_commands, mock_set_insights_operator_and_crd_installed_state, \
    HelmCommand, HelmCommandInsightsInstall, HelmCommandOperatorInstall, HelmCommandDelete, cleanup_env_globals

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


def common_get_existing_crds(crds: List[str]) -> List[str]:
    return crds


def install_mocks(mocker, k8s):
    mocker.patch.object(pyk8s.models.V1Namespace, "ensure", utils.return_none)
    mocker.patch(fun_assembly_create_assemblies_from_file, return_true_list)
    utils.mock_validate_secret(mocker)
    utils.mock_kube_secret_api(k8s,
                               read=partial(
                                   mocked_read_secret,
                                   image_pull_secret_name=default_docker_config_secret_name)
                               )
    mock_get_operator_version(mocker)
    mock_copy_secret(mocker, k8s)
    mock_subprocess_run(mocker)

def uninstall_mocks(mocker, k8s):
    mocker.patch(fun_assembly_get_assemblies_list, mocked_get_assemblies_list)
    mocker.patch(fun_common_get_existing_crds, common_get_existing_crds)
    mocker.patch(fun_common_delete_crd, common_delete_crd)
    mocker.patch(fun_install_insights_installed, utils.return_true)
    mocker.patch(fun_assembly_backup_assemblies, mocked_backup_assemblies)
    mocker.patch(fun_assembly_delete_running_assemblies, return_true_list)
    mocker.patch(fun_install_operator_versions, mocked_installed_operator_versions)
    mocks.mock_assembly_list(k8s)

def upgrade_mocks(mocker, k8s):
    install_mocks(mocker, k8s)
    uninstall_mocks(mocker, k8s)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    utils.mock_helm_get_values(mocker, fake_values)
    utils.mock_helm_env(mocker)
    mock_delete_crd(mocker, k8s)
    mocker.patch(fun_get_helm_version_checked, mocked_helm_version_checked)
    mocker.patch('kxicli.commands.install.read_cached_crd_files', mock_read_cached_crd_data)


@dataclass
class HelmCommandAzureInstall(HelmCommandInsightsInstall):
    version: str = fake_version
    values: str = 'values.yaml'
    chart: str = f'{fake_chart_repo_url}/insights'
    keycloak_importUsers: Optional[str] = 'false'


@dataclass
class HelmCommandAzureOperator(HelmCommandOperatorInstall):
    chart: str = f'{fake_chart_repo_url}/kxi-operator'
    release: str = test_operator_helm_name


@dataclass
class HelmCommandFetch(HelmCommand):
    version: str = fake_version
    repo: str = fake_chart_repo_url
    chart: str = ''

    def cmd(self):
        return ['helm', 'fetch',
                f'{self.repo}/{self.chart}',
                '--destination', os.getcwd() + '/tests/files/helm',
                '--version', self.version,
                ]


# Tests

def test_install(mocker: MockerFixture, cleanup_env_globals, k8s):
    mocker.patch(fun_get_helm_version_checked, mocked_helm_version_checked)
    mocker.patch('kxicli.commands.install.get_installed_charts', lambda *args: [])
    mocker.patch(fun_install_operator_versions, lambda *args: ([], []))
    install_mocks(mocker, k8s)

    runner = CliRunner()
    with utils.temp_file(file_name='values.yaml') as values_file:
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
    expected_helm_commands = [
        HelmCommandAzureOperator(values=values_file,
                                 release=default_insights_release
                                 ),
        HelmCommandAzureInstall(values=values_file,
                                keycloak_importUsers='true'
                                )
    ]
    install_upgrade_checks(actual_res,
                           helm_commands=expected_helm_commands,
                           expected_subprocess_args=[True, None, None],
                           expected_delete_crd_params=[],
                           expected_running_assembly={}
                           )


def test_uninstall(mocker: MockerFixture, cleanup_env_globals, k8s):
    mocker.patch(fun_get_helm_version_checked, mocked_helm_version_checked)
    uninstall_mocks(mocker, k8s)
    mock_subprocess_run(mocker)

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
    check_subprocess_run_commands(
        [
            HelmCommandDelete(),
            HelmCommandDelete(release='test-op-helm',
                              namespace='kxi-operator'
                              ),
        ]
    )


def test_upgrade(mocker: MockerFixture, cleanup_env_globals, k8s):
    upgrade_mocks(mocker, k8s)
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
    expected_helm_commands = [
                              HelmCommandFetch(chart='kxi-operator'),
                              HelmCommandAzureOperator(values=values_file_name),
                              HelmCommandFetch(chart='insights'),
                              HelmCommandAzureInstall(values=values_file_name)
    ]
    install_upgrade_checks(result,
                           helm_commands=expected_helm_commands,
                           expected_subprocess_args=[True, None, None],
                           expected_running_assembly={}
                           )


def test_upgrade_with_no_assemblies_running(mocker: MockerFixture, cleanup_env_globals, k8s):
    global delete_crd_params
    delete_crd_params = []
    upgrade_mocks(mocker, k8s)

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
    expected_helm_commands = [
                              HelmCommandFetch(chart='kxi-operator'),
                              HelmCommandAzureOperator(values=values_file_name),
                              HelmCommandFetch(chart='insights'),
                              HelmCommandAzureInstall(values=values_file_name)
    ]
    install_upgrade_checks(result,
                           helm_commands=expected_helm_commands,
                           expected_subprocess_args=[True, None, None],
                           expected_running_assembly={}
                           )


def test_upgrade_with_chart_repo_url(mocker: MockerFixture, cleanup_env_globals, k8s):
    test_chart_repo_url = 'oci://test_chart_repo_url'
    upgrade_mocks(mocker, k8s)

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
    expected_helm_commands = [
                              HelmCommandFetch(repo=test_chart_repo_url, chart='kxi-operator'),
                              HelmCommandAzureOperator(values=values_file_name,
                                                       chart=f'{test_chart_repo_url}/kxi-operator'
                                                       ),
                              HelmCommandFetch(repo=test_chart_repo_url, chart='insights'),
                              HelmCommandAzureInstall(values=values_file_name,
                                                      chart=f'{test_chart_repo_url}/insights'
                                                      )
                              ]
    install_upgrade_checks(result,
                           helm_commands=expected_helm_commands,
                           expected_subprocess_args=[True, None, None],
                           expected_running_assembly={}
                           )


def test_upgrade_without_filepath(mocker: MockerFixture, cleanup_env_globals, k8s):
    upgrade_mocks(mocker, k8s)

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
    expected_helm_commands = [
                              HelmCommandFetch(chart='kxi-operator'),
                              HelmCommandAzureOperator(values='-'),
                              HelmCommandFetch(chart='insights'),
                              HelmCommandAzureInstall(values='-')
    ]
    install_upgrade_checks(result,
                           helm_commands=expected_helm_commands,
                           expected_subprocess_args=[True, fake_values_yaml, True],
                           expected_running_assembly={}
                           )
