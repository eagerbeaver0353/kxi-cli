from __future__ import annotations

import sys

import click
import pyk8s
from pathlib import Path
import subprocess
import tarfile
from requests.exceptions import HTTPError

from kxicli import config
from kxicli import log
from kxicli import phrases

token_cache_path = Path.home() / '.insights'
token_cache_dir = str(token_cache_path)
token_cache_file = str(token_cache_path / 'credentials')

key_install_outputFile = 'install.outputFile'
key_chart_repo_name = 'chart.repo.name'
key_chart_repo_url = 'chart.repo.url'
key_chart_repo_username = 'chart.repo.username'
key_chart_repo_password = 'chart.repo.password'
key_client_cert_secret = 'client.cert.secret'
key_ingress_cert_secret = 'ingress.cert.secret'
key_ingress_cert = 'ingress.cert'
key_ingress_key ='ingress.key'
key_ingress_certmanager_disabled = 'ingress.certmanager.disabled'
key_image_repository = 'image.repository'
key_image_repository_user = 'image.repository.user'
key_image_repository_password = 'image.repository.password'
key_image_pullSecret = 'image.pullSecret'
key_keycloak_secret = 'keycloak.secret'
key_keycloak_admin_password = 'keycloak.admin.password'
key_keycloak_management_password = 'keycloak.management.password'
key_keycloak_postgresqlSecret = 'keycloak.postgresqlSecret'
key_keycloak_realm = 'realm'
key_postgresql_postgres_password = 'postgresql.postgres.password'
key_postgresql_user_password = 'postgresql.user.password'
key_keycloak_authURL = 'keycloak.authURL'
key_license_secret = 'license.secret'
key_license_envVar = 'license.as-env-var'
key_license_filepath = 'license.filepath'
key_gui_client_secret = 'guiClientSecret'
key_operator_client_secret = 'operatorClientSecret'
key_install_filepath = 'install.filepath'
key_assembly_backup_file = 'assembly.backup.file'
key_release_name = 'release.name'
key_namespace = 'namespace'
key_hostname = 'hostname'
key_version = 'version'
key_operator_version = 'operator.version'
key_client_id = 'client.id'
key_client_secret = 'client.secret'
key_admin_username = 'admin.username'
key_serviceaccount_id = 'auth.serviceaccount.id'
key_serviceaccount_secret = 'auth.serviceaccount.secret'
key_cache_file = 'cache.file'
key_auth_client = 'auth.client'

# Help text dictionary for commands
HELP_TEXT = {
    key_hostname: 'Hostname of kdb Insights deployment',
    key_namespace: 'Kubernetes namespace',
    key_client_id: 'Client ID to request an access token with',
    key_client_secret: 'Client secret to request an access token with',
    key_serviceaccount_id: 'Service account ID to request an access token with',
    key_serviceaccount_secret: 'Service account secret to request an access token with',
    key_chart_repo_name: 'Name for chart repository',
    key_chart_repo_url: 'Repository URL to pull charts from',
    key_chart_repo_username: 'Username for the chart repository',
    key_chart_repo_password: 'Password for the chart repository',
    key_license_secret: 'Secret containing kdb+ license',
    key_license_envVar: 'Mount kdb+ license secret as an environment variable',
    key_license_filepath: 'File path and file name of kdb+ license file',
    key_client_cert_secret: 'Secret containing TLS cert and key for client issuer',
    key_image_repository: 'Repository to pull images from',
    key_image_repository_user: 'User name for image repository',
    key_image_repository_password: 'Password for image repository',
    key_image_pullSecret: 'Secret containing credentials for the image repository ',
    key_keycloak_secret: 'Secret containing Keycloak admin password',
    key_keycloak_admin_password: 'Keycloak Admin password',
    key_keycloak_management_password: 'Keycloak WildFly Management password',
    key_keycloak_postgresqlSecret: 'Secret containing Keycloak postgresql passwords',
    key_postgresql_postgres_password: 'Postgresql postgres password',
    key_postgresql_user_password: 'Postgresql user password',
    key_keycloak_authURL: 'Auth URL for Keycloak',
    key_ingress_cert_secret: 'Secret containing self-managed TLS cert and key for the ingress',
    key_ingress_cert: 'File path to TLS certificate for the ingress',
    key_ingress_key: 'File path to TLS private key for the ingress',
    key_ingress_certmanager_disabled: 'Flag to disable usage of TLS certmanager',
    key_install_outputFile: 'Name for the generated values file',
    key_install_filepath: 'Values file to install with',
    key_assembly_backup_file: 'Filepath to store state of running assemblies',
    key_release_name: 'Release name for the install',
    key_gui_client_secret: 'Keycloak client secret for gui service account',
    key_operator_client_secret: 'Keycloak client secret for operator service account',
    key_keycloak_realm: 'Name of Keycloak realm',
    key_version: 'Version to install',
    key_operator_version: 'Version of the operator to install',
    key_admin_username: 'Administrator username'
}

# Default values for commands if needed
DEFAULT_VALUES = {
    key_license_secret: 'kxi-license',
    key_license_envVar: False,
    key_client_cert_secret: 'kxi-certificate',
    key_chart_repo_name: 'kx-insights',
    key_chart_repo_url: 'https://nexus.dl.kx.com/repository/kx-insights-charts',
    key_image_pullSecret: 'kxi-nexus-pull-secret',
    key_image_repository: 'registry.dl.kx.com',
    key_keycloak_secret: 'kxi-keycloak',
    key_keycloak_postgresqlSecret: 'kxi-postgresql',
    key_ingress_cert_secret: 'kxi-ingress-cert',
    key_install_outputFile: 'values.yaml',
    key_assembly_backup_file: 'kxi-assembly-state.yaml',
    key_release_name: 'insights',
    key_keycloak_realm: 'insights',
    key_admin_username: 'user',
    key_cache_file: token_cache_file,
    key_auth_client: 'insights-app'
}

# Flag to indicate if k8s.config.load_config has already been called
CONFIG_ALREADY_LOADED = False


def get_help_text(option):
    """Get help text for an option from configuration"""
    if option in HELP_TEXT:
        return HELP_TEXT[option]

    return ''


def get_default_val(option):
    """Get default value for an option from configuration"""
    if option and config.config.has_option(config.config.default_section, option):
        return config.config.get(config.config.default_section, option)

    if option in DEFAULT_VALUES:
        return DEFAULT_VALUES[option]

    return None

def sanitize_hostname(raw_string):
    """Sanitize a hostname to allow it to be used"""
    return raw_string.replace('http://', '').replace('https://', '').rstrip('/')

def is_interactive_session():
    return sys.stdout.isatty() and '--force' not in sys.argv


def read_crd(name):
    try:
        return pyk8s.cl.customresourcedefinitions.get(name)
    except Exception as exception:
        raise click.ClickException(
            f'Exception when while trying to find CustomResourceDefinition({name}): {exception}'
        ) from exception

def crd_exists(name):
    return isinstance(read_crd(name), pyk8s.models.V1CustomResourceDefinition)

def get_existing_crds(names):
    crds = []
    for n in names:
        if crd_exists(n):
            crds.append(n)
    return crds

def replace_crd(name: str, body):
    click.echo(f'Replacing CRD {name}')
    try:
        pyk8s.cl.customresourcedefinitions.delete(name, wait=True, grace_period_seconds=0, force=True)
    except pyk8s.exceptions.NotFoundError:
        pass
    except Exception as exception:
        raise click.ClickException(
            f"Exception when trying to delete CustomResourceDefinition({name}): {exception}"
        ) from exception

    try:
        return pyk8s.cl.customresourcedefinitions.create(body)
    except Exception as exception:
        raise click.ClickException(
            f'Exception when trying to create CustomResourceDefinition({name}): {exception}'
        ) from exception



def delete_crd(name):
    click.echo(f'Deleting CRD {name}')

    try:
        pyk8s.cl.customresourcedefinitions.delete(name)
    except Exception as exception:
        raise click.ClickException(
            f'Exception when trying to delete CustomResourceDefinition({name}): {exception}'
        ) from exception

def extract_files_from_tar(tar: Path, files: list, max_read_size: int = 2000000):
    data = []
    if tar.exists() and tarfile.is_tarfile(tar):
        log.debug(f'Opening tar file {tar} to extract files')
        with tarfile.open(tar) as tf:
            for file in files:
                log.debug(f'Attempting to extract {file} from {tar}')
                try:
                    f = tf.extractfile(file)
                    raw = f.read(max_read_size)
                    f.close()
                    if len(raw) < max_read_size:
                        data.append(raw)
                    else:
                        raise click.ClickException(f'Refused to load more than {max_read_size} bytes from {file}')
                except KeyError:
                    raise click.ClickException(f'File {file} not found in {tar}')
    else:
        raise click.ClickException(f'{tar} does not exist or is not a valid tar archive')
    return data


def enter_password(msg: str):
    password = click.prompt(msg, type=click.STRING, hide_input=True).strip()
    confirm_password = click.prompt(phrases.password_reenter, type=click.STRING, hide_input=True).strip()

    if password != confirm_password:
        log.error(phrases.password_no_match)
        password = enter_password(msg)

    return password

def try_decode(msg: bytes | str, **decode_args):
    if isinstance(msg, bytes):
        try:
            msg = msg.decode(**decode_args)
        except AttributeError:
            msg = 'Could not decode message'
    elif msg is None:
        msg = ''
    return msg


def parse_called_process_error(exception: subprocess.CalledProcessError, encoding: str = 'utf-8'):
    stdout = try_decode(exception.stdout, encoding=encoding)
    stderr = try_decode(exception.stderr, encoding=encoding)

    # reconstruct the failed command into something that can be copy/pasted
    command = " ".join(exception.cmd)

    return f'Command "{command}" failed with output:\n {stdout} {stderr}'

def parse_http_exception(e: HTTPError):
    res = e.response
    if "errorMessage" in res.json():
        msg = res.json()["errorMessage"]
    elif "error" in res.json():
        msg = res.json()["error"]
    else:
        msg = res
    return res, msg


def handle_http_exception(e: HTTPError, prefix: str):
    if hasattr(e, "response"):
        res, msg = parse_http_exception(e)
        raise click.ClickException(f"{prefix} {res.status_code} {res.reason} ({msg})")
    else:
        raise click.ClickException(str(e))
