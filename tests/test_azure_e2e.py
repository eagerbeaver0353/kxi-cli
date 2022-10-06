import typing
from pathlib import Path

from click import BaseCommand
from click.testing import CliRunner
from pytest_mock import MockerFixture

from kxicli import config
from kxicli import main
from kxicli.commands.azure import default_insights_namespace
from kxicli.common import get_default_val
from test_azure import fun_assembly_create_assemblies_from_file, _create_assemblies_from_file, \
    fun_assembly_delete_running_assemblies, _delete_running_assemblies, \
    fun_assembly_backup_assemblies, _backup_assemblies, _backup_no_assemblies, fake_version, fake_values_yaml, \
    read_secret, fun_subprocess_run, subprocess_run_helm_success, install_create_namespace, \
    fun_assembly_get_assemblies_list, _get_assemblies_list, _get_assemblies_list_raise_apiexception_404, \
    helm_version_checked, fun_install_operator_installed, install_operator_installed, fun_common_get_existing_crds, \
    common_get_existing_crds, fun_common_delete_crd, fun_install_insights_installed, install_insights_installed, \
    fun_install_create_namespace
from utils import temp_file, mock_kube_secret_api

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

fun_get_helm_version_checked: str = 'kxicli.commands.common.helm.get_helm_version_checked'


def common_delete_crd(crd):
    """tst"""
    pass


def get_helm_version_checked():
    return helm_version_checked


def test_assembly_restore(mocker: MockerFixture):
    mocker.patch(fun_assembly_create_assemblies_from_file, _create_assemblies_from_file)

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
                '--assembly-backup-filepath', asm_file,
                '--force'
            ],
            env=default_env
        )
        assert result.exit_code == 0


def test_assembly_delete(mocker: MockerFixture):
    mocker.patch(fun_assembly_delete_running_assemblies, _delete_running_assemblies)
    mocker.patch(fun_assembly_get_assemblies_list, _get_assemblies_list)

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


def test_assembly_backup(mocker: MockerFixture):
    mocker.patch(fun_assembly_backup_assemblies, _backup_assemblies)
    mocker.patch(fun_assembly_get_assemblies_list, _get_assemblies_list)

    runner = CliRunner()
    with temp_file(default_assembly_backup_file) as asm_file:
        with open(asm_file, mode='w') as f:
            f.write(a_test_asm_str)
        result = runner.invoke(
            typing.cast(BaseCommand, main.cli),
            args=[
                'azure',
                'assembly',
                'backup',
                '--assembly-backup-filepath', asm_file
            ],
            env=default_env
        )
        assert result.exit_code == 0


def test_install(mocker: MockerFixture):
    mock_kube_secret_api(mocker, read=read_secret)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success)
    mocker.patch(fun_install_create_namespace, install_create_namespace)
    mocker.patch(fun_get_helm_version_checked, get_helm_version_checked)
    mocker.patch(fun_assembly_create_assemblies_from_file, _create_assemblies_from_file)

    runner = CliRunner()
    with temp_file(default_assembly_backup_file) as asm_file:
        with open(asm_file, mode='w') as f:
            f.write(a_test_asm_str)
        with temp_file(file_name='values.yaml') as values_file:
            with open(values_file, mode='w') as vf:
                vf.write(fake_values_yaml)
            result = runner.invoke(
                typing.cast(BaseCommand, main.cli),
                args=[
                    'azure',
                    'install',
                    '--version', fake_version,
                    '--operator-version', fake_version,
                    '--assembly-backup-filepath', asm_file,
                    '--filepath', values_file,
                    '--force'
                ],
                env=default_env
            )
            assert result.exit_code == 0


def test_uninstall(mocker: MockerFixture):
    mocker.patch(fun_assembly_get_assemblies_list, _get_assemblies_list)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success)
    mocker.patch(fun_install_operator_installed, install_operator_installed)
    mocker.patch(fun_common_get_existing_crds, common_get_existing_crds)
    mocker.patch(fun_common_delete_crd, common_delete_crd)
    mocker.patch(fun_install_insights_installed, install_insights_installed)
    mocker.patch(fun_assembly_backup_assemblies, _backup_assemblies)
    mocker.patch(fun_assembly_delete_running_assemblies, _delete_running_assemblies)
    mocker.patch(fun_assembly_get_assemblies_list, _get_assemblies_list)
    mocker.patch(fun_get_helm_version_checked, get_helm_version_checked)

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


def test_upgrade(mocker: MockerFixture):
    mock_kube_secret_api(mocker, read=read_secret)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success)
    mocker.patch(fun_install_create_namespace, install_create_namespace)
    mocker.patch(fun_get_helm_version_checked, get_helm_version_checked)
    mocker.patch(fun_assembly_create_assemblies_from_file, _create_assemblies_from_file)
    mocker.patch(fun_assembly_get_assemblies_list, _get_assemblies_list)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success)
    mocker.patch(fun_install_operator_installed, install_operator_installed)
    mocker.patch(fun_common_get_existing_crds, common_get_existing_crds)
    mocker.patch(fun_common_delete_crd, common_delete_crd)
    mocker.patch(fun_install_insights_installed, install_insights_installed)
    mocker.patch(fun_assembly_backup_assemblies, _backup_assemblies)
    mocker.patch(fun_assembly_delete_running_assemblies, _delete_running_assemblies)
    mocker.patch(fun_get_helm_version_checked, get_helm_version_checked)

    runner = CliRunner()
    with temp_file(default_assembly_backup_file) as asm_file:
        with open(asm_file, mode='w') as f:
            f.write(a_test_asm_str)
        with temp_file(file_name='values.yaml') as values_file:
            with open(values_file, mode='w') as vf:
                vf.write(fake_values_yaml)
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

def test_upgrade_with_no_assemblies_running(mocker: MockerFixture):
    mock_kube_secret_api(mocker, read=read_secret)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success)
    mocker.patch(fun_install_create_namespace, install_create_namespace)
    mocker.patch(fun_get_helm_version_checked, get_helm_version_checked)
    mocker.patch(fun_assembly_create_assemblies_from_file, _create_assemblies_from_file)
    mocker.patch(fun_assembly_get_assemblies_list, _get_assemblies_list_raise_apiexception_404)
    mocker.patch(fun_subprocess_run, subprocess_run_helm_success)
    mocker.patch(fun_install_operator_installed, install_operator_installed)
    mocker.patch(fun_common_get_existing_crds, common_get_existing_crds)
    mocker.patch(fun_common_delete_crd, common_delete_crd)
    mocker.patch(fun_install_insights_installed, install_insights_installed)
    mocker.patch(fun_assembly_backup_assemblies, _backup_no_assemblies)
    mocker.patch(fun_assembly_delete_running_assemblies, _delete_running_assemblies)
    mocker.patch(fun_get_helm_version_checked, get_helm_version_checked)

    runner = CliRunner()
    with temp_file(file_name='values.yaml') as values_file:
        with open(values_file, mode='w') as vf:
            vf.write(fake_values_yaml)
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
