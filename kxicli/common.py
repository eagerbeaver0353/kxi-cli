import sys

import click
import kubernetes as k8s
from pathlib import Path
import requests
import tarfile

from kxicli import config
from kxicli import log
from kxicli import phrases


key_install_outputFile = 'install.outputFile'
key_chart_repo_name = 'chart.repo.name'
key_chart_repo_url = 'chart.repo.url'
key_chart_repo_username = 'chart.repo.username'
key_chart_repo_password = 'chart.repo.password'
key_client_cert_secret = 'client.cert.secret'
key_install_config_secret = 'install.configSecret'
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

# Help text dictionary for commands
HELP_TEXT = {
    key_hostname: 'Hostname of Insights deployment',
    key_namespace: 'Kubernetes namespace',
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
    key_install_config_secret: 'Secret containing helm install values',
    key_install_filepath: 'Values file to install with',
    key_assembly_backup_file: 'Filepath to store state of running assemblies',
    key_release_name: 'Release name for the install',
    key_gui_client_secret: 'Keycloak client secret for gui service account',
    key_operator_client_secret: 'Keycloak client secret for operator service account',
    key_keycloak_realm: 'Name of Keycloak realm',
    key_version: 'Version to install',
    key_operator_version: 'Version of the operator to install'
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
    key_install_config_secret: 'kxi-install-config',
    key_assembly_backup_file: 'kxi-assembly-state.yaml',
    key_release_name: 'insights',
    key_keycloak_realm: 'insights',
    key_namespace: 'kxi'
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


def get_access_token(hostname, client_id, client_secret, realm):
    """Get Keycloak client access token"""
    log.debug('Requesting access token')
    url = f'{hostname}/auth/realms/{realm}/protocol/openid-connect/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }

    r = requests.post(url, headers=headers, data=payload)
    if r:
        return r.json()['access_token']

    raise click.ClickException('Failed to request access token')


def get_admin_token(hostname, username, password):
    """Get Keycloak Admin API token from hostname"""
    log.debug('Requesting admin access token')
    url = f'{hostname}/auth/realms/master/protocol/openid-connect/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    payload = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': 'admin-cli'
    }
    r = requests.post(url, headers=headers, data=payload)
    if r:
        return r.json()['access_token']

    raise click.ClickException('Failed to request admin access token')


def load_kube_config():
    global CONFIG_ALREADY_LOADED        
    if not CONFIG_ALREADY_LOADED:        
        try:
            k8s.config.load_incluster_config()                    
        except k8s.config.ConfigException:
            try:
                k8s.config.load_kube_config()
            except k8s.config.ConfigException:
                raise click.ClickException("Kubernetes cluster config not found")                                  
    CONFIG_ALREADY_LOADED = True

def read_crd(name):
    load_kube_config()
    api = k8s.client.ApiextensionsV1Api()

    try:
        return api.read_custom_resource_definition(name)
    except k8s.client.rest.ApiException as exception:
        if exception.status == 404:
            return None
        else:
            click.echo(f'Exception when calling ApiextensionsV1Api->read_custom_resource_definition: {exception}')

def crd_exists(name):
    return isinstance(read_crd(name), k8s.client.V1CustomResourceDefinition)

def get_existing_crds(names):
    crds = []
    for n in names:
        if crd_exists(n):
            crds.append(n)
    return crds

def create_or_replace_crd(name, body):
    load_kube_config()
    api = k8s.client.ApiextensionsV1Api()
    existing_crd = read_crd(name)
    if isinstance(existing_crd, k8s.client.V1CustomResourceDefinition):
        body['metadata']['resourceVersion'] = existing_crd.metadata.resource_version
        api.replace_custom_resource_definition(name, body)
    else:
        api.create_custom_resource_definition(body)

def replace_crd(name, body):
    click.echo(f'Replacing CRD {name}')
    try:
        create_or_replace_crd(name, body)
    except k8s.client.rest.ApiException as exception:
        # can occur if metadata.resourceVersion is out of date so try and reapply
        if exception.status == 409:
            create_or_replace_crd(name, body)
        else:
            click.echo(f'Exception when trying to replace custom resource definition: {exception}')

def delete_crd(name):
    load_kube_config()
    api = k8s.client.ApiextensionsV1Api()

    click.echo(f'Deleting CRD {name}')
    try:
        api.delete_custom_resource_definition(name)
    except k8s.client.rest.ApiException as exception:
        click.echo(f'Exception when calling ApiextensionsV1Api->delete_custom_resource_definition: {exception}')

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