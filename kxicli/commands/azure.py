from functools import partial
from typing import Optional

import click
import yaml
from click import ClickException

from kxicli.commands import assembly as assembly_lib
from kxicli.commands import install as install_lib
from kxicli.commands.common.arg import arg_force, arg_filepath, arg_operator_version as arg_common_operator_version, \
    arg_version, arg_release as arg_common_release, arg_namespace, arg_assembly_backup_filepath
from kxicli.common import get_help_text as help_text
from kxicli.resources import secret

default_insights_namespace: str = 'insights'
default_insights_release: str = 'insights'

default_values_secret_name: str = 'kxi-config'
default_values_secret_data_name: str = 'kxi-config.yaml'

default_docker_config_secret_name: str = 'kxi-acr-pull-secret'


# Possible arguments

arg_release = partial(
    arg_common_release, default=default_insights_release
)
arg_operator_version = partial(
    arg_common_operator_version, required=True
)


@click.group()
def azure():
    """Insights Azure related commands"""

@azure.command()
@arg_namespace()
@arg_release()
@arg_version()
@arg_operator_version()
@arg_filepath()
@arg_assembly_backup_filepath()
@arg_force()
@click.pass_context
def upgrade(
        ctx,
        namespace: str,
        release: str,
        version: str,
        operator_version: str,
        filepath: Optional[str] = None,
        assembly_backup_filepath: Optional[str] = None,
        force: bool = False
):
    """Upgrade kdb Insights Enterprise"""

    # Prepare

    values: str = get_values(values_file=filepath, insights_namespace=namespace)

    chart_repo_url: str = get_repo_url(values)
   
    ctx.invoke(install_lib.upgrade,
                namespace=namespace,
                release=release,
                version=version,
                operator_version=operator_version,
                filepath=filepath,
                chart_repo_url=chart_repo_url,
                image_pull_secret=default_docker_config_secret_name,
                assembly_backup_filepath=assembly_backup_filepath,
                install_config_secret=default_values_secret_name,
                install_config_secret_data_name=default_values_secret_data_name,
                force=force
    )

    click.secho(f'\nUpgrade to KXI Operator {operator_version} and Insights {version} complete', bold=True)


@azure.command()
@arg_namespace()
@arg_release()
@arg_assembly_backup_filepath()
@arg_force()
def uninstall(
        namespace: str,
        release: str,
        assembly_backup_filepath: Optional[str] = None,
        force: bool = False
):
    """Uninstall kdb Insights Enterprise"""
    click.secho('Uninstalling kdb Insights Enterprise', bold=True)

    # Backup
    assembly_lib.backup_assemblies(
        namespace=namespace,
        filepath=assembly_backup_filepath,
        force=force
    )

    # Uninstall
    
    install_lib.delete_release_operator_and_crds(release=release,
                                                 namespace=namespace,
                                                 force=force,
                                                 uninstall_operator=True
    )

    click.secho('kdb Insights Enterprise uninstalled', bold=True)


@azure.command()
@arg_namespace()
@arg_release()
@arg_version()
@arg_operator_version()
@arg_filepath()
@arg_force()
@click.pass_context
def install(
        ctx,
        namespace: str,
        release: str,
        version: str,
        operator_version: str,
        filepath: Optional[str] = None,
        force: bool = False
):
    """Install kdb Insights Enterprise"""

    values: str = get_values(values_file=filepath, insights_namespace=namespace)

    chart_repo_url: str = get_repo_url(values)
  
    ctx.invoke(install_lib.run,
                namespace=namespace,
                release=release,
                version=version,
                operator_version=operator_version,
                filepath=filepath,
                chart_repo_url=chart_repo_url,
                image_pull_secret=default_docker_config_secret_name,
                install_config_secret=default_values_secret_name,
                install_config_secret_data_name=default_values_secret_data_name,
                force=force
    )

    click.secho(f'\nInstall of KXI Operator {operator_version} and Insights {version} complete', bold=True)


@azure.group()
def assembly():
    """Assembly related commands"""


@assembly.command()
@arg_namespace()
@arg_assembly_backup_filepath()
@arg_force()
def backup(
        namespace: str,
        assembly_backup_filepath: Optional[str] = None,
        force: bool = False
):
    """Back up running assemblies to a file"""

    assembly_lib.backup_assemblies(namespace, assembly_backup_filepath, force)


@assembly.command()
@arg_namespace()
@arg_force()
def delete(
        namespace: str,
        force: bool = False
):
    """Delete assemblies"""
    assembly_lib.delete_running_assemblies(
        namespace=namespace,
        wait=True,
        force=force
    )


@assembly.command()
@arg_namespace()
@arg_assembly_backup_filepath()
def restore(
        namespace: str,
        assembly_backup_filepath: Optional[str] = None,
):
    """Restore assemblies"""

    assembly_lib.create_assemblies_from_file(
        filepath=assembly_backup_filepath,
        namespace=namespace,
        use_kubeconfig=False,
    )

def get_values(
        values_file: Optional[str],
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
    else:
        values = install_lib.get_secret(
            secret_object=secret.Secret(insights_namespace, secret_name),
            secret_data_name=secret_data_name
        )
        if not values:
            raise ClickException('Values not found stored in the deployment. --filepath must be provided')
        return values


def get_repo_url(values: str) -> str:
    values_dict: dict = yaml.safe_load(values)

    global_image_repository: str = values_dict['global']['image']['repository']
    # we only need the first part of the url
    return f'oci://{global_image_repository.split("/")[0]}'
