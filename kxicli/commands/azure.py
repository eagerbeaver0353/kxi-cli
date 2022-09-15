import base64
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from functools import partial, lru_cache
from pathlib import Path
from typing import Optional, List

import click
import kubernetes as k8s
import requests
import yaml
from click import ClickException
from kubernetes.client import V1Secret
from packaging.version import Version

from kxicli import common
from kxicli import log
from kxicli.commands import assembly as assembly_lib
from kxicli.commands import install as install_lib
from kxicli.commands.common import arg_force, arg_filepath, arg_operator_version as arg_common_operator_version, \
    arg_version, arg_release as arg_common_release, arg_namespace as arg_common_namespace, arg_assembly_backup_filepath
from kxicli.common import get_help_text as help_text
from kxicli.resources import secret

default_insights_namespace: str = 'insights'
default_kxi_operator_namespace: str = 'kxi-operator'
default_insights_release: str = 'insights'
default_kxi_operator_release: str = 'kxi-operator'

default_values_secret_name: str = 'kxi-config'
default_values_secret_data_name: str = 'kxi-config.yaml'

default_docker_config_secret_name: str = 'kxi-acr-pull-secret'
default_docker_config_secret_data_name: str = '.dockerconfigjson'


class RequiredHelmVersion(Version):
    pass


class LocalHelmVersion(Version):
    pass


minimum_helm_version: str = '3.8.0'
required_helm_version: RequiredHelmVersion = RequiredHelmVersion(version=minimum_helm_version)

# Possible arguments

arg_namespace = partial(
    arg_common_namespace, default=default_insights_namespace
)
arg_operator_namespace = partial(
    click.option, '--operator-namespace', default=default_kxi_operator_namespace, help=help_text('namespace'),
    type=click.STRING
)
arg_release = partial(
    arg_common_release, default=default_insights_release
)
arg_operator_release = partial(
    click.option, '--operator-release', default=default_kxi_operator_release, help=help_text('release.name'),
    type=click.STRING
)
arg_operator_version = partial(
    arg_common_operator_version, required=True
)
arg_values_url = partial(
    click.option, '--values-url', help='Values URL to install with',
    type=click.STRING
)


@click.group()
def azure():
    """Insights Azure related commands"""


@azure.command()
@arg_namespace()
@arg_operator_namespace()
@arg_release()
@arg_operator_release()
@arg_version()
@arg_operator_version()
@arg_filepath()
@arg_values_url()
@arg_assembly_backup_filepath()
@arg_force()
def upgrade(
        namespace: str,
        operator_namespace: str,
        release: str,
        operator_release: str,
        version: str,
        operator_version: str,
        filepath: Optional[str] = None,
        values_url: Optional[str] = None,
        assembly_backup_filepath: Optional[str] = None,
        force: bool = False
):
    """Upgrade KX Insights"""

    click.secho('Upgrading KX Insights', bold=True)

    # Prepare

    is_interactive_exec: bool = not force

    values: str = get_values(values_file=filepath, values_url=values_url, insights_namespace=namespace)

    chart_repo_url: str = get_repo_url(values)

    docker_config: str = get_docker_config(kxi_operator_namespace=operator_namespace)

    assemblies: List = get_assemblies(insights_namespace=namespace)

    # Backup

    assembly_backup_filepath = backup_assemblies(
        insights_namespace=namespace,
        assemblies=assemblies,
        assembly_backup_filepath=assembly_backup_filepath
    )

    # Uninstall

    delete_assemblies(
        assemblies=assemblies,
        insights_namespace=namespace,
        is_interactive_exec=is_interactive_exec
    )

    uninstall_insights(
        insights_release=release,
        insights_namespace=namespace,
        is_interactive_exec=is_interactive_exec,
        helm_version_checked=get_helm_version_checked()
    )

    uninstall_kxi_operator(
        kxi_operator_release=operator_release,
        kxi_operator_namespace=operator_namespace,
        is_interactive_exec=is_interactive_exec,
        helm_version_checked=get_helm_version_checked()
    )

    delete_crds(is_interactive_exec=is_interactive_exec)

    # Re-install

    install_kxi_operator(
        release=operator_release,
        namespace=operator_namespace,
        version=operator_version,
        chart_repo_url=chart_repo_url,
        values=values,
        docker_config=docker_config,
        helm_version_checked=get_helm_version_checked()
    )

    install_insights(
        release=release,
        namespace=namespace,
        version=version,
        chart_repo_url=chart_repo_url,
        values=values,
        docker_config=docker_config,
        helm_version_checked=get_helm_version_checked()
    )

    # Restore

    restore_assemblies(
        insights_namespace=namespace,
        assembly_backup_filepath=assembly_backup_filepath,
        is_interactive_exec=is_interactive_exec
    )

    click.secho(f'\nUpgrade to KXI Operator {operator_version} and Insights {version} complete', bold=True)


@azure.command()
@arg_namespace()
@arg_operator_namespace()
@arg_release()
@arg_operator_release()
@arg_assembly_backup_filepath()
@arg_force()
def uninstall(
        namespace: str,
        operator_namespace: str,
        release: str,
        operator_release: str,
        assembly_backup_filepath: Optional[str] = None,
        force: bool = False
):
    """Uninstall KX Insights"""
    click.secho('Uninstalling KX Insights', bold=True)

    # Prepare

    is_interactive_exec: bool = not force

    assemblies: List = get_assemblies(insights_namespace=namespace)

    # Backup

    backup_assemblies(
        insights_namespace=namespace,
        assemblies=assemblies,
        assembly_backup_filepath=assembly_backup_filepath
    )

    # Uninstall

    delete_assemblies(
        assemblies=assemblies,
        insights_namespace=namespace,
        is_interactive_exec=is_interactive_exec
    )

    uninstall_insights(
        insights_release=release,
        insights_namespace=namespace,
        is_interactive_exec=is_interactive_exec,
        helm_version_checked=get_helm_version_checked()
    )

    uninstall_kxi_operator(
        kxi_operator_release=operator_release,
        kxi_operator_namespace=operator_namespace,
        is_interactive_exec=is_interactive_exec,
        helm_version_checked=get_helm_version_checked()
    )

    delete_crds(is_interactive_exec=is_interactive_exec)

    click.secho('KX Insights uninstalled', bold=True)


@azure.command()
@arg_namespace()
@arg_operator_namespace()
@arg_release()
@arg_operator_release()
@arg_version()
@arg_operator_version()
@arg_filepath()
@arg_values_url()
@arg_assembly_backup_filepath()
@arg_force()
def install(
        namespace: str,
        operator_namespace: str,
        release: str,
        operator_release: str,
        version: str,
        operator_version: str,
        filepath: Optional[str] = None,
        values_url: Optional[str] = None,
        assembly_backup_filepath: Optional[str] = None,
        force: bool = False
):
    """Install KX Insights"""

    click.secho('Installing KX Insights', bold=True)

    is_interactive_exec: bool = not force

    values: str = get_values(values_file=filepath, values_url=values_url, insights_namespace=namespace)

    chart_repo_url: str = get_repo_url(values)

    docker_config: str = get_docker_config(kxi_operator_namespace=operator_namespace)

    install_kxi_operator(
        release=operator_release,
        namespace=operator_namespace,
        version=operator_version,
        chart_repo_url=chart_repo_url,
        values=values,
        docker_config=docker_config,
        helm_version_checked=get_helm_version_checked()
    )

    install_insights(
        release=release,
        namespace=namespace,
        version=version,
        chart_repo_url=chart_repo_url,
        values=values,
        docker_config=docker_config,
        helm_version_checked=get_helm_version_checked()
    )

    # Restore

    restore_assemblies(
        insights_namespace=namespace,
        assembly_backup_filepath=assembly_backup_filepath,
        is_interactive_exec=is_interactive_exec
    )

    click.secho(f'\nInstall of KXI Operator {operator_version} and Insights {version} complete', bold=True)


@azure.group()
def assembly():
    """Assembly related commands"""


@assembly.command()
@arg_namespace()
@arg_assembly_backup_filepath()
def backup(
        namespace: str,
        assembly_backup_filepath: Optional[str] = None
):
    """Backup assemblies"""
    assemblies: List = get_assemblies(insights_namespace=namespace)

    backup_assemblies(
        insights_namespace=namespace,
        assemblies=assemblies,
        assembly_backup_filepath=assembly_backup_filepath
    )


@assembly.command()
@arg_namespace()
@arg_force()
def delete(
        namespace: str,
        force: bool = False
):
    """Delete assemblies"""
    is_interactive_exec: bool = not force

    assemblies: List = get_assemblies(insights_namespace=namespace)

    delete_assemblies(
        assemblies=assemblies,
        insights_namespace=namespace,
        is_interactive_exec=is_interactive_exec
    )


@assembly.command()
@arg_namespace()
@arg_assembly_backup_filepath()
@arg_force()
def restore(
        namespace: str,
        assembly_backup_filepath: Optional[str] = None,
        force: bool = False
):
    """Restore assemblies"""
    is_interactive_exec: bool = not force

    restore_assemblies(
        insights_namespace=namespace,
        assembly_backup_filepath=assembly_backup_filepath,
        is_interactive_exec=is_interactive_exec
    )


# Prepare

class HelmVersionChecked:
    def __init__(self, req_helm_version: RequiredHelmVersion, local_helm_version: LocalHelmVersion) -> None:
        if local_helm_version < req_helm_version:
            raise ClickException(f'Local helm version {local_helm_version} is lower then required {req_helm_version}')

    def ok(self):
        """
        To prevent variable unused.
        """


# @cache
# can't use cache cause of 3.8 compatibility
@lru_cache(maxsize=None)
def get_helm_version_checked() -> HelmVersionChecked:
    return HelmVersionChecked(
        req_helm_version=required_helm_version,
        local_helm_version=_get_helm_version()
    )


def get_secret(namespace: str, secret_name: str, secret_data_name: str, msg: str) -> str:
    s: V1Secret = secret.Secret(namespace, secret_name).read()
    if s is not None:
        return base64.b64decode(s.data[secret_data_name]).decode('ascii')
    else:
        raise ClickException(msg)


def get_values(
        values_file: Optional[str],
        values_url: Optional[str],
        insights_namespace: str = default_insights_namespace,
        secret_name: str = default_values_secret_name,
        secret_data_name: str = default_values_secret_data_name
) -> str:
    if values_file is not None:
        with open(values_file) as f:
            try:
                return f.read()
            except (IOError, ValueError, EOFError, FileNotFoundError):  # pragma: no cover
                raise ClickException(f'Invalid values file {values_file}')
    elif values_url is not None:
        return requests.get(values_url, allow_redirects=True).text
    else:
        return get_secret(
            namespace=insights_namespace,
            secret_name=secret_name,
            secret_data_name=secret_data_name,
            msg='Values not found stored in the deployment. Either --values-file or --values-url must be provided'
        )


def get_repo_url(values: str) -> str:
    values_dict: dict = yaml.safe_load(values)

    global_image_repository: str = values_dict['global']['image']['repository']
    # we only need the first part of the url
    return f'oci://{global_image_repository.split("/")[0]}'


def get_docker_config(
        kxi_operator_namespace: str = default_kxi_operator_namespace,
        secret_name: str = default_docker_config_secret_name,
        secret_data_name: str = default_docker_config_secret_data_name
) -> str:
    return get_secret(
        namespace=kxi_operator_namespace,
        secret_name=secret_name,
        secret_data_name=secret_data_name,
        msg='Docker config secret not found in Cluster'
    )


def get_assemblies(insights_namespace: str) -> List:
    try:
        return assembly_lib._get_assemblies_list(insights_namespace).get('items')
    except k8s.client.exceptions.ApiException as exception:
        # 404 is returned when there are no assemblies
        if exception.status == 404:
            return []
        else:
            raise exception


# Backup

def backup_assemblies(insights_namespace: str, assemblies: List, assembly_backup_filepath: str) -> Optional[str]:
    if len(assemblies) > 0:
        click.secho('\nBacking up assemblies', bold=True)
        return assembly_lib._backup_assemblies(insights_namespace, assembly_backup_filepath, force=False)
    return None


# Uninstall

def delete_assemblies(assemblies: List, insights_namespace: str, is_interactive_exec: bool) -> List[bool]:
    if len(assemblies) > 0 and \
            _prompt_if_interactive_exec(
                is_interactive_exec=is_interactive_exec,
                message=f'{len(assemblies)} assemblies deployed. Do you want to delete?'
            ):
        click.secho('\nTearing down assemblies', bold=True)
        return assembly_lib._delete_running_assemblies(namespace=insights_namespace, wait=True, force=False)
    return []


def uninstall_insights(
        insights_namespace: str, insights_release: str, is_interactive_exec: bool,
        helm_version_checked: HelmVersionChecked
) -> Optional[subprocess.CompletedProcess]:
    if install_lib.insights_installed(insights_release, namespace=insights_namespace) and \
            _prompt_if_interactive_exec(
                is_interactive_exec=is_interactive_exec,
                message='KX Insights is deployed. Do you want to uninstall?'
            ):
        return _helm_uninstall(
            release=insights_release, namespace=insights_namespace, helm_version_checked=helm_version_checked
        )
    return None


def uninstall_kxi_operator(
        kxi_operator_namespace: str, kxi_operator_release: str, is_interactive_exec: bool,
        helm_version_checked: HelmVersionChecked
) -> Optional[subprocess.CompletedProcess]:
    if install_lib.operator_installed(release=kxi_operator_release, namespace=kxi_operator_namespace) and \
            _prompt_if_interactive_exec(
                is_interactive_exec=is_interactive_exec,
                message='The kxi-operator is deployed. Do you want to uninstall?'
            ):
        return _helm_uninstall(
            release=kxi_operator_release, namespace=kxi_operator_namespace, helm_version_checked=helm_version_checked
        )
    return None


def delete_crds(is_interactive_exec: bool):
    crds = common.get_existing_crds(['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com'])
    if len(crds) > 0 and \
            _prompt_if_interactive_exec(
                is_interactive_exec=is_interactive_exec,
                message=f'The assemblies CRDs {crds} exist. Do you want to delete them?'
            ):
        for i in crds:
            common.delete_crd(i)


# Re-install

def install_kxi_operator(
        release: str, namespace: str, version: str, chart_repo_url: str, values: str,
        docker_config: str, helm_version_checked: HelmVersionChecked
) -> subprocess.CompletedProcess:
    click.secho('\nReinstalling kxi-operator', bold=True)
    return _helm_install(
        release, chart=f'{chart_repo_url}/kxi-operator', values=values, version=version, namespace=namespace,
        docker_config=docker_config, helm_version_checked=helm_version_checked
    )


def install_insights(
        release: str, namespace: str, version: str, chart_repo_url: str, values: str, docker_config: str,
        helm_version_checked: HelmVersionChecked
) -> subprocess.CompletedProcess:
    click.secho('\nReinstalling insights', bold=True)
    return _helm_install(
        release, chart=f'{chart_repo_url}/insights', values=values, version=version, namespace=namespace,
        docker_config=docker_config, helm_version_checked=helm_version_checked
    )


# Restore

def restore_assemblies(insights_namespace: str, assembly_backup_filepath: str, is_interactive_exec: bool):
    if assembly_backup_filepath is not None:
        assembly_backup_file = Path(assembly_backup_filepath)
        if not assembly_backup_file.exists() or \
                not assembly_backup_file.is_file() or \
                not os.access(assembly_backup_filepath, os.R_OK):
            raise click.ClickException(f'Assembly backup file was provided but not accessible during restore phase')
        else:
            if _prompt_if_interactive_exec(
                    is_interactive_exec=is_interactive_exec,
                    message='Restore assemblies from the backup?'
            ):
                click.secho('\nReapplying assemblies', bold=True)
                assembly_lib._create_assemblies_from_file(
                    namespace=insights_namespace, filepath=assembly_backup_filepath
                )


# Utils

def _prompt_if_interactive_exec(is_interactive_exec: bool, message: str) -> bool:
    if not is_interactive_exec:
        return True
    else:
        return click.confirm(f'\n{message}', abort=True)


@contextmanager
def _temp_docker_config(docker_config: str):
    temp_dir: str = str(tempfile.mkdtemp())
    try:
        with open(Path(temp_dir).joinpath('config.json'), 'w') as docker_config_json:
            docker_config_json.write(docker_config)
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir)


def _helm_install(
        release: str, helm_version_checked: HelmVersionChecked, chart: str, values: str, version: str,
        namespace: str, docker_config: str
) -> subprocess.CompletedProcess:
    """Call 'helm install' using subprocess.run
    """

    helm_version_checked.ok()

    base_command: List[str] = ['helm', 'install', '-f', '-', release, chart]

    if version:
        base_command = base_command + ['--version', version]

    if namespace:
        base_command = base_command + ['--namespace', namespace]
        install_lib.create_namespace(namespace)

    try:
        log.debug(f'Install command {base_command}')
        with _temp_docker_config(docker_config) as temp_dir:
            helm_env = os.environ.copy()
            helm_env['DOCKER_CONFIG'] = temp_dir
            return subprocess.run(base_command, check=True, input=values, text=True, env=helm_env)
    except subprocess.CalledProcessError as e:
        raise ClickException(str(e))


def _helm_uninstall(release, helm_version_checked: HelmVersionChecked, namespace=None) -> subprocess.CompletedProcess:
    """Call 'helm uninstall' using subprocess.run"""

    helm_version_checked.ok()

    msg = f'Uninstalling release {release}'

    base_command = ['helm', 'uninstall', release]

    if namespace:
        base_command = base_command + ['--namespace', namespace]
        msg = f'{msg} in namespace {namespace}'

    click.echo(msg)

    try:
        log.debug(f'Uninstall command {base_command}')
        return subprocess.run(base_command, check=True)
    except subprocess.CalledProcessError as e:
        raise ClickException(str(e))


def _get_helm_version() -> LocalHelmVersion:
    command: List[str] = ['helm', 'version', "--template={{.Version}}"]
    try:
        version: str = subprocess.check_output(command, text=True)
        return LocalHelmVersion(version=version)
    except subprocess.CalledProcessError as e:
        raise ClickException(str(e))
