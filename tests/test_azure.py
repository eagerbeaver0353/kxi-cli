import base64
from functools import partial
from pathlib import Path
from subprocess import CompletedProcess, CalledProcessError
from typing import List, Optional

import click
import pytest
import requests_mock
import yaml
from kubernetes.client import V1Secret
from kubernetes.client.exceptions import ApiException
from pytest_mock import MockerFixture

from kxicli.commands.azure import LocalHelmVersion, minimum_helm_version, _get_helm_version, _helm_install, \
    HelmVersionChecked, required_helm_version, default_insights_release, _helm_uninstall, _prompt_if_interactive_exec, \
    restore_assemblies, default_insights_namespace, install_insights, install_kxi_operator, \
    default_kxi_operator_release, default_kxi_operator_namespace, delete_crds, uninstall_kxi_operator, \
    uninstall_insights, delete_assemblies, backup_assemblies, get_assemblies, get_docker_config, get_repo_url, \
    get_values, get_helm_version_checked
from kxicli.common import get_default_val as default_val
from utils import temp_file

# fun names

fun_subprocess_check_out: str = 'subprocess.check_output'
fun_subprocess_run: str = 'subprocess.run'
fun_install_create_namespace: str = 'kxicli.commands.install.create_namespace'
fun_click_confirm: str = 'click.confirm'
fun_assembly_create_assemblies_from_file: str = 'kxicli.commands.assembly._create_assemblies_from_file'
fun_common_get_existing_crds: str = 'kxicli.common.get_existing_crds'
fun_common_delete_crd: str = 'kxicli.common.delete_crd'
fun_install_operator_installed: str = 'kxicli.commands.install.operator_installed'
fun_install_insights_installed: str = 'kxicli.commands.install.insights_installed'
fun_assembly_delete_running_assemblies: str = 'kxicli.commands.assembly._delete_running_assemblies'
fun_assembly_backup_assemblies: str = 'kxicli.commands.assembly._backup_assemblies'
fun_assembly_get_assemblies_list: str = 'kxicli.commands.assembly._get_assemblies_list'
fun_install_read_secret: str = 'kxicli.commands.install.read_secret'

fake_docker_config: dict = {
    'asdf': 'asdf'
}
fake_docker_config_yaml: str = yaml.dump(fake_docker_config)
local_minimum_helm_version: LocalHelmVersion = LocalHelmVersion(minimum_helm_version)
helm_version_checked: HelmVersionChecked = HelmVersionChecked(
    req_helm_version=required_helm_version,
    local_helm_version=local_minimum_helm_version
)
whatever_str: str = 'whatever'
fake_version: str = '1.1.0'
fake_chart_repo: str = 'kxinsightsprod.azurecr.io'
fake_chart_repo_url: str = f'oci://{fake_chart_repo}'
fake_values: dict = {
    'global': {
        'image': {
            'repository': f'{fake_chart_repo}/images/kx-insights'
        }
    }
}
fake_values_str: str = yaml.dump(fake_values)

fake_helm_version_checked: HelmVersionChecked = HelmVersionChecked(
    req_helm_version=required_helm_version,
    local_helm_version=LocalHelmVersion(minimum_helm_version)
)
fake_assemblies: List[str] = ['asdf']

fake_docker_config_secret: V1Secret = V1Secret(
    data={
        '.dockerconfigjson': base64.b64encode(fake_docker_config_yaml.encode('ascii'))
    }
)
config_json_file_name: str = 'config.json'


class FakeK8SCustomResource:
    @staticmethod
    def get(key: str) -> List[str]:
        return fake_assemblies


# mocks

def install_create_namespace(name: str):
    """tst"""
    pass


def subprocess_check_out_helm_version_valid(*popenargs, timeout=None, **kwargs) -> str:
    return f'v{minimum_helm_version}'


def subprocess_check_out_helm_version_invalid(*popenargs, timeout=None, **kwargs) -> str:
    return 'v3.7.0'


def subprocess_check_out_helm_version_exception(*popenargs, timeout=None, **kwargs) -> str:
    raise CalledProcessError(returncode=1, cmd=popenargs[0])


def subprocess_run_helm_success(
        *popenargs,
        input=None, capture_output=False, timeout=None, check=False, **kwargs
):
    return CompletedProcess(args=popenargs[0], returncode=0, stdout='', stderr='')


def subprocess_run_helm_fail(
        *popenargs,
        input=None, capture_output=False, timeout=None, check=False, **kwargs
):
    raise CalledProcessError(returncode=1, cmd=popenargs[0])


def subprocess_run_helm_success_install_with_res(
        *popenargs, res: dict,
        input=None, capture_output=False, timeout=None, check=False, **kwargs
):
    env: dict = kwargs['env']
    res['env'] = env
    res['cmd'] = popenargs[0]
    res['DOCKER_CONFIG'] = env['DOCKER_CONFIG']
    with open(str(Path(env['DOCKER_CONFIG']) / config_json_file_name)) as dc:
        res['dockerconfigjson'] = dc.read()
    return CompletedProcess(args=popenargs[0], returncode=0, stdout='', stderr='')


def subprocess_run_helm_success_uninstall_with_res(
        *popenargs, res: dict,
        input=None, capture_output=False, timeout=None, check=False, **kwargs
):
    res['cmd'] = popenargs[0]
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


def click_confirm_no(
        text: str,
        default: Optional[bool] = False,
        abort: bool = False,
        prompt_suffix: str = ": ",
        show_default: bool = True,
        err: bool = False,
) -> bool:
    return False


def _create_assemblies_from_file(namespace, filepath, wait=None):
    """tst"""
    pass


def common_get_existing_crds(crds: List[str]) -> List[str]:
    return crds


def install_operator_installed(release: str, namespace: str = default_kxi_operator_namespace) -> bool:
    return True


def install_operator_installed_not(release: str, namespace: str = default_kxi_operator_namespace) -> bool:
    return False


def install_insights_installed(release: str, namespace: str = default_kxi_operator_namespace) -> bool:
    return True


def install_insights_installed_not(release: str, namespace: str = default_kxi_operator_namespace) -> bool:
    return False


def _delete_running_assemblies(namespace: str, wait: bool, force: bool) -> List[bool]:
    return [True]


def _backup_assemblies(namespace: str, filepath: str, force: bool):
    return filepath


def _get_assemblies_list(namespace: str) -> FakeK8SCustomResource:
    return FakeK8SCustomResource()


def _get_assemblies_list_raise_apiexception_404(namespace: str) -> FakeK8SCustomResource:
    raise ApiException(status=404)


def _get_assemblies_list_raise_apiexception_other(namespace: str) -> FakeK8SCustomResource:
    raise ApiException()


def read_secret(namespace: str, name: str) -> Optional[V1Secret]:
    return fake_docker_config_secret


def read_secret_fail(namespace: str, name: str) -> Optional[V1Secret]:
    return None


def compare_completed_process(cp1: CompletedProcess, cp2: CompletedProcess) -> bool:
    return cp1.args == cp2.args and \
           cp1.returncode == cp2.returncode and \
           cp1.stdout == cp2.stdout and \
           cp1.stderr == cp2.stderr


# tests

def test_helm_version_valid(mocker: MockerFixture):
    mocker.patch(fun_subprocess_check_out, subprocess_check_out_helm_version_valid)
    assert _get_helm_version() >= LocalHelmVersion(version=minimum_helm_version)


def test_helm_version_invalid(mocker: MockerFixture):
    mocker.patch(fun_subprocess_check_out, subprocess_check_out_helm_version_invalid)
    assert _get_helm_version() < LocalHelmVersion(version=minimum_helm_version)


def test_helm_version_exception(mocker: MockerFixture):
    mocker.patch(fun_subprocess_check_out, subprocess_check_out_helm_version_exception)
    with pytest.raises(click.ClickException):
        assert _get_helm_version()


def test_helm_install_success(mocker: MockerFixture):
    res: dict = {}
    expected_cmd: List[str] = [
        'helm', 'install', '-f', '-', default_insights_release, whatever_str,
        '--version', whatever_str,
        '--namespace', whatever_str
    ]

    subprocess_run_helm_success_helm_install = partial(subprocess_run_helm_success_install_with_res, res=res)

    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install)
    mocker.patch(fun_install_create_namespace, install_create_namespace)

    actual_res = _helm_install(
        release=default_insights_release,
        helm_version_checked=helm_version_checked,
        chart=whatever_str,
        values=whatever_str,
        version=whatever_str,
        namespace=whatever_str,
        docker_config=fake_docker_config_yaml
    )
    assert 'DOCKER_CONFIG' in dict(res['env'])
    assert res['dockerconfigjson'] == fake_docker_config_yaml
    assert res['cmd'] == expected_cmd
    assert compare_completed_process(
        actual_res,
        CompletedProcess(args=expected_cmd, returncode=0, stdout='', stderr='')
    )


def test_helm_install_fail(mocker: MockerFixture):
    mocker.patch(fun_subprocess_run, subprocess_run_helm_fail)
    mocker.patch(fun_install_create_namespace, install_create_namespace)
    with pytest.raises(click.ClickException):
        _helm_install(
            release=default_insights_release,
            helm_version_checked=helm_version_checked,
            chart=whatever_str,
            values=whatever_str,
            version=whatever_str,
            namespace=whatever_str,
            docker_config=fake_docker_config_yaml
        )


def test_helm_uninstall_success(mocker: MockerFixture):
    res: dict = {}
    expected_cmd: List[str] = [
        'helm', 'uninstall', default_insights_release, '--namespace', whatever_str
    ]
    expected_res: CompletedProcess = CompletedProcess(args=expected_cmd, returncode=0, stdout='', stderr='')

    subprocess_run_helm_success_uninstall = partial(subprocess_run_helm_success_uninstall_with_res, res=res)

    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_uninstall)
    mocker.patch(fun_install_create_namespace, install_create_namespace)
    actual_res = _helm_uninstall(
        release=default_insights_release,
        helm_version_checked=helm_version_checked,
        namespace=whatever_str
    )
    assert compare_completed_process(actual_res, expected_res)
    assert res['cmd'] == expected_cmd


def test_helm_uninstall_fail(mocker: MockerFixture):
    mocker.patch(fun_subprocess_run, subprocess_run_helm_fail)
    mocker.patch(fun_install_create_namespace, install_create_namespace)
    with pytest.raises(click.ClickException):
        _helm_uninstall(
            release=default_insights_release,
            helm_version_checked=helm_version_checked,
            namespace=whatever_str
        )


def test_prompt_if_interactive_exec_yes(mocker: MockerFixture):
    mocker.patch(fun_click_confirm, click_confirm_yes)
    assert _prompt_if_interactive_exec(True, "")


def test_prompt_if_interactive_exec_no(mocker: MockerFixture):
    mocker.patch(fun_click_confirm, click_confirm_no)
    assert not _prompt_if_interactive_exec(True, "")


def test_prompt_if_interactive_exec_not():
    assert _prompt_if_interactive_exec(False, "")


def test_restore_assemblies_exists(mocker: MockerFixture):
    asm_file_content: str = 'a test asm file'
    res: dict = {}

    def _create_assemblies_from_file_exists(namespace, filepath, wait=None):
        res['filepath'] = filepath
        with open(filepath, 'r') as af:
            res['asm_file_content'] = af.read()

    mocker.patch(fun_assembly_create_assemblies_from_file, _create_assemblies_from_file_exists)
    mocker.patch(fun_click_confirm, click_confirm_yes)
    with temp_file(default_val('assembly.backup.file')) as asm_file:
        with open(asm_file, mode='w') as f:
            f.write(asm_file_content)
        restore_assemblies(
            insights_namespace=default_insights_namespace,
            assembly_backup_filepath=asm_file,
            is_interactive_exec=True
        )
        assert asm_file == res['filepath']
    assert asm_file_content == res['asm_file_content']


def test_restore_assemblies_not_exists(mocker: MockerFixture):
    mocker.patch(fun_assembly_create_assemblies_from_file, _create_assemblies_from_file)
    mocker.patch(fun_click_confirm, click_confirm_yes)
    with temp_file(default_val('assembly.backup.file')) as asm_file:
        with pytest.raises(click.ClickException):
            restore_assemblies(
                insights_namespace=default_insights_namespace,
                assembly_backup_filepath=asm_file,
                is_interactive_exec=True
            )


def test_install_insights_helm_success(mocker: MockerFixture):
    res: dict = {}
    expected_cmd: List[str] = [
        'helm', 'install', '-f', '-', default_insights_release, f'{fake_chart_repo_url}/insights',
        '--version', fake_version,
        '--namespace', default_insights_namespace
    ]

    subprocess_run_helm_success_helm_install_insights = partial(subprocess_run_helm_success_install_with_res, res=res)

    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_insights)
    mocker.patch(fun_install_create_namespace, install_create_namespace)
    actual_res = install_insights(
        release=default_insights_release,
        namespace=default_insights_namespace,
        version=fake_version,
        chart_repo_url=fake_chart_repo_url,
        values=fake_values_str,
        docker_config=fake_docker_config_yaml,
        helm_version_checked=helm_version_checked
    )
    assert 'DOCKER_CONFIG' in dict(res['env'])
    assert res['dockerconfigjson'] == fake_docker_config_yaml
    assert res['cmd'] == expected_cmd
    assert compare_completed_process(
        actual_res,
        CompletedProcess(args=expected_cmd, returncode=0, stdout='', stderr='')
    )


def test_install_kxi_operator(mocker: MockerFixture):
    res: dict = {}
    expected_cmd: List[str] = [
        'helm', 'install', '-f', '-', default_kxi_operator_release, f'{fake_chart_repo_url}/kxi-operator',
        '--version', fake_version,
        '--namespace', default_kxi_operator_namespace
    ]

    subprocess_run_helm_success_helm_install_kxi_operator = partial(
        subprocess_run_helm_success_install_with_res, res=res
    )

    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_helm_install_kxi_operator)
    mocker.patch(fun_install_create_namespace, install_create_namespace)
    actual_res = install_kxi_operator(
        release=default_kxi_operator_release,
        namespace=default_kxi_operator_namespace,
        version=fake_version,
        chart_repo_url=fake_chart_repo_url,
        values=fake_values_str,
        docker_config=fake_docker_config_yaml,
        helm_version_checked=helm_version_checked
    )
    assert 'DOCKER_CONFIG' in dict(res['env'])
    assert res['dockerconfigjson'] == fake_docker_config_yaml
    assert res['cmd'] == expected_cmd
    assert compare_completed_process(
        actual_res,
        CompletedProcess(args=expected_cmd, returncode=0, stdout='', stderr='')
    )


def test_delete_crds(mocker: MockerFixture):
    res: dict = {'crds': []}

    def common_delete_crd(crd: str):
        res['crds'].append(crd)

    expected_crds = ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com']
    mocker.patch(fun_click_confirm, click_confirm_yes)
    mocker.patch(fun_common_get_existing_crds, common_get_existing_crds)
    mocker.patch(fun_common_delete_crd, common_delete_crd)
    delete_crds(False)
    assert expected_crds == res['crds']


def test_uninstall_kxi_operator(mocker: MockerFixture):
    res: dict = {}
    expected_cmd: List[str] = [
        'helm', 'uninstall', default_kxi_operator_release, '--namespace', default_kxi_operator_namespace
    ]
    expected_res: CompletedProcess = CompletedProcess(args=expected_cmd, returncode=0, stdout='', stderr='')

    subprocess_run_helm_success_uninstall_kxi_operator = partial(
        subprocess_run_helm_success_uninstall_with_res, res=res
    )

    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_uninstall_kxi_operator)
    mocker.patch(fun_install_operator_installed, install_operator_installed)
    actual_res = uninstall_kxi_operator(
        kxi_operator_namespace=default_kxi_operator_namespace,
        kxi_operator_release=default_kxi_operator_release,
        is_interactive_exec=False,
        helm_version_checked=helm_version_checked
    )
    assert compare_completed_process(actual_res, expected_res)
    assert res['cmd'] == expected_cmd


def test_uninstall_kxi_operator_not(mocker: MockerFixture):
    mocker.patch(fun_install_operator_installed, install_operator_installed_not)
    actual_res = uninstall_kxi_operator(
        kxi_operator_namespace=default_kxi_operator_namespace,
        kxi_operator_release=default_kxi_operator_release,
        is_interactive_exec=False,
        helm_version_checked=helm_version_checked
    )
    assert actual_res is None


def test_uninstall_insights(mocker: MockerFixture):
    res: dict = {}
    expected_cmd: List[str] = ['helm', 'uninstall', default_insights_release, '--namespace', default_insights_namespace]
    completed_res: CompletedProcess = CompletedProcess(args=expected_cmd, returncode=0, stdout='', stderr='')

    subprocess_run_helm_success_uninstall_insights = partial(subprocess_run_helm_success_uninstall_with_res, res=res)

    mocker.patch(fun_subprocess_run, subprocess_run_helm_success_uninstall_insights)
    mocker.patch(fun_install_insights_installed, install_insights_installed)
    actual_res = uninstall_insights(
        insights_namespace=default_insights_namespace,
        insights_release=default_insights_release,
        is_interactive_exec=False,
        helm_version_checked=helm_version_checked
    )
    assert res['cmd'] == expected_cmd
    assert compare_completed_process(actual_res, completed_res)


def test_uninstall_insights_not(mocker: MockerFixture):
    mocker.patch(fun_install_insights_installed, install_insights_installed_not)
    actual_res = uninstall_insights(
        insights_namespace=default_insights_namespace,
        insights_release=default_insights_release,
        is_interactive_exec=False,
        helm_version_checked=helm_version_checked
    )
    assert actual_res is None


def test_delete_assemblies(mocker: MockerFixture):
    mocker.patch(fun_assembly_delete_running_assemblies, _delete_running_assemblies)
    assert delete_assemblies(
        assemblies=['asdf'],
        insights_namespace=default_insights_namespace,
        is_interactive_exec=False
    ) == [True]


def test_delete_assemblies_none(mocker: MockerFixture):
    mocker.patch(fun_assembly_delete_running_assemblies, _delete_running_assemblies)
    assert delete_assemblies(
        assemblies=[],
        insights_namespace=default_insights_namespace,
        is_interactive_exec=False
    ) == []


def test_backup_assemblies(mocker: MockerFixture):
    mocker.patch(fun_assembly_backup_assemblies, _backup_assemblies)
    assert backup_assemblies(
        insights_namespace=default_insights_namespace,
        assemblies=['asdf'],
        assembly_backup_filepath='asdf'
    ) == 'asdf'


def test_backup_assemblies_none(mocker: MockerFixture):
    mocker.patch(fun_assembly_backup_assemblies, _backup_assemblies)
    assert backup_assemblies(
        insights_namespace=default_insights_namespace,
        assemblies=[],
        assembly_backup_filepath='asdf'
    ) is None


def test_get_assemblies(mocker: MockerFixture):
    mocker.patch(fun_assembly_get_assemblies_list, _get_assemblies_list)
    assert get_assemblies(
        insights_namespace=default_insights_namespace
    ) == fake_assemblies


def test_get_assemblies_raise_apiexception(mocker: MockerFixture):
    mocker.patch(fun_assembly_get_assemblies_list, _get_assemblies_list_raise_apiexception_404)
    assert get_assemblies(
        insights_namespace=default_insights_namespace
    ) == []


def test_get_assemblies_raise_exception(mocker: MockerFixture):
    mocker.patch(fun_assembly_get_assemblies_list, _get_assemblies_list_raise_apiexception_other)
    with pytest.raises(ApiException):
        get_assemblies(
            insights_namespace=default_insights_namespace
        )


def test_get_docker_config(mocker: MockerFixture):
    mocker.patch(fun_install_read_secret, read_secret)
    assert get_docker_config(
        kxi_operator_namespace=default_kxi_operator_namespace
    ) == fake_docker_config_yaml


def test_get_docker_config_fail(mocker: MockerFixture):
    mocker.patch(fun_install_read_secret, read_secret_fail)
    with pytest.raises(click.ClickException):
        get_docker_config(
            kxi_operator_namespace=default_kxi_operator_namespace
        )


def test_get_repo_url():
    assert get_repo_url(fake_values_str) == fake_chart_repo_url


def test_get_values_both_none():
    with pytest.raises(click.ClickException):
        get_values(
            values_file=None,
            values_url=None
        )


def test_get_values_url_only():
    fake_values_url: str = "https://my-values-url.com/values.yaml"
    with requests_mock.Mocker() as m:
        m.get(fake_values_url, text=fake_values_str)
        assert get_values(
            values_file=None,
            values_url=fake_values_url
        ) == fake_values_str


def test_get_values_file_only():
    with temp_file(file_name='values.yaml') as values_file:
        with open(values_file, mode='w') as vf:
            vf.write(fake_values_str)
        assert get_values(
            values_file=values_file,
            values_url=None
        ) == fake_values_str


def test_get_values_file_not_exists():
    with pytest.raises(FileNotFoundError):
        with temp_file(file_name='values.yaml') as values_file:
            get_values(
                values_file=values_file,
                values_url=None
            )


def test_get_helm_version_checked(mocker: MockerFixture):
    mocker.patch(fun_subprocess_check_out, subprocess_check_out_helm_version_valid)
    assert type(get_helm_version_checked()) is HelmVersionChecked


def test_get_helm_version_checked_fail():
    with pytest.raises(click.ClickException):
        HelmVersionChecked(
            req_helm_version=required_helm_version,
            local_helm_version=LocalHelmVersion(subprocess_check_out_helm_version_invalid([]))
        )
