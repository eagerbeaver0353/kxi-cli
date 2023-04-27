from __future__ import annotations

import base64
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

import click
import semver
import re
import kubernetes as k8s
import yaml
from click import ClickException
from click_aliases import ClickAliasedGroup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, asymmetric, hashes

from kxicli import common
from kxicli import log
from kxicli import options
from kxicli import phrases
from kxicli.cli_group import cli
from kxicli.commands import assembly
from kxicli.commands.common import arg
from kxicli.commands.common.namespace import create_namespace
from kxicli.common import get_default_val as default_val, key_gui_client_secret, key_operator_client_secret
from kxicli.resources import secret, helm, helm_chart

DOCKER_CONFIG_FILE_PATH = str(Path.home() / '.docker' / 'config.json')
operator_namespace = 'kxi-operator'
operator_release_name = 'app.kubernetes.io/instance'

SECRET_TYPE_TLS = 'kubernetes.io/tls'
SECRET_TYPE_DOCKERCONFIG_JSON = 'kubernetes.io/dockerconfigjson'
SECRET_TYPE_OPAQUE = 'Opaque'

TLS_CRT = 'tls.crt'
TLS_KEY = 'tls.key'
DOCKER_SECRET_KEY = '.dockerconfigjson'


# Basic validation for secrets
KEYCLOAK_KEYS =  ('admin-password', 'management-password')
POSTGRESQL_KEYS =  ('postgres-password', 'password')
LICENSE_KEYS = ('license',)
IMAGE_PULL_KEYS =  (DOCKER_SECRET_KEY,)
INGRESS_CERT_KEYS = (TLS_CRT, TLS_KEY)
CLIENT_CERT_KEYS = (TLS_CRT, TLS_KEY)

CRD_FILES = [
    'insights.kx.com_assemblies.yaml',
    'insights.kx.com_assemblyresources.yaml'
]

CRD_NAMES = [
    'assemblies.insights.kx.com', 
    'assemblyresources.insights.kx.com'
]

license_key = 'license.secret'
image_pull_key = 'image.pullSecret'


@cli.group('install', cls=ClickAliasedGroup, aliases=['azure'])
def install():
    """Insights installation commands"""

@install.command()
@arg.install_setup_group
@arg.ingress_certmanager_disabled()
@arg.output_file()
def setup(namespace, chart_repo_name, chart_repo_url, chart_repo_username,
          license_secret, license_as_env_var, license_filepath,
          client_cert_secret, image_repo, image_repo_user, image_pull_secret, gui_client_secret, operator_client_secret,
          keycloak_secret, keycloak_postgresql_secret, keycloak_auth_url, hostname,
          ingress_cert_secret, ingress_cert, ingress_key, ingress_certmanager_disabled,
          output_file, **kwargs):
    """Perform necessary setup steps to install Insights"""

    click.secho(phrases.header_setup, bold=True)
    namespace = options.namespace.prompt(namespace)
    create_namespace(namespace)

    try:
        _, active_context = k8s.config.list_kube_config_contexts()
        click.echo(phrases.ns_and_cluster.format(namespace=namespace, \
            cluster=active_context["context"]["cluster"]))
    except k8s.config.ConfigException:
        try:
            k8s.config.load_incluster_config()
            click.echo(f'Running in namespace {namespace} in-cluster')
        except k8s.config.ConfigException:
            raise click.ClickException("Kubernetes cluster config not found")

    # Setup secret by looking for them in the following hierarchy
    #   - cmd line arg
    #      - values file (currently None in this command)
    #          - value configured in cli-config file
    #            - value in DEFAULT_VALUES
    license_secret = lookup_secret(namespace, license_secret, None, license_key)
    client_cert_secret = lookup_secret(namespace, client_cert_secret, None, 'client.cert.secret')
    image_pull_secret = lookup_secret(namespace, image_pull_secret, None, image_pull_key)
    keycloak_secret = lookup_secret(namespace, keycloak_secret, None, 'keycloak.secret')
    keycloak_postgresql_secret = lookup_secret(namespace, keycloak_postgresql_secret, None, 'keycloak.postgresqlSecret')
    ingress_cert_secret_object = lookup_secret(namespace, ingress_cert_secret, None, 'ingress.cert.secret')

    click.secho(phrases.header_ingress, bold=True)
    hostname = sanitize_ingress_host(options.hostname.prompt(hostname))
    ingress_certmanager_disabled, use_tls_secret, ingress_cert_secret_object = \
        prompt_for_ingress_cert(ingress_cert_secret_object, ingress_cert_secret, ingress_cert, ingress_key, ingress_certmanager_disabled)

    click.secho(phrases.header_chart, bold=True)
    chart_repo_name = options.chart_repo_name.prompt(chart_repo_name)
    if any (chart_repo_name == item['name'] for item in helm.repo_list()):
       click.echo(f'Using existing helm repo {chart_repo_name}')
    else:
        chart_repo_url = options.chart_repo_url.prompt(chart_repo_url)
        username = options.chart_repo_username.prompt(chart_repo_username)
        password = options.chart_repo_password.prompt()
        helm.add_repo(chart_repo_name, chart_repo_url, username, password)

    click.secho(phrases.header_license, bold=True)
    license_secret, license_on_demand = prompt_for_license(license_secret, license_filepath, license_as_env_var)

    click.secho(phrases.header_image, bold=True)
    image_repo, image_pull_secret = prompt_for_image_details(image_pull_secret, image_repo, image_repo_user)

    click.secho(phrases.header_client_cert, bold=True)
    client_cert_secret = ensure_secret(client_cert_secret, populate_cert)

    click.secho(phrases.header_keycloak, bold=True)
    if deploy_keycloak():
        keycloak_secret = ensure_secret(keycloak_secret, populate_keycloak_secret)
        keycloak_postgresql_secret = ensure_secret(keycloak_postgresql_secret, populate_postgresql_secret)

    gui_client_secret = options.gui_client_secret.prompt(gui_client_secret)
    common.config.update_config(profile=common.config.config.default_section, name=key_gui_client_secret,
                                        value=gui_client_secret)

    operator_client_secret = options.operator_client_secret.prompt(operator_client_secret)
    common.config.update_config(profile=common.config.config.default_section, name=key_operator_client_secret,
                                        value=operator_client_secret)


    # These keys must all exist, conditionally defined
    # keys like the self-managed ingress cert are handled afterwards
    install_file = {
        'global': {
            'ingress': {
                'host': hostname
            },
            'license': {
                'secretName': license_secret.name
            },
            'caIssuer': {
                'name': client_cert_secret.name,
                'secretName': client_cert_secret.name
            },
            'image': {
                'repository': image_repo
            },
            'imagePullSecrets': [
                {
                    'name': image_pull_secret.name
                }
            ],
            'keycloak': {
                'guiClientSecret': gui_client_secret,
                'operatorClientSecret': operator_client_secret
            }
        }
    }

    if deploy_keycloak():
        install_file['keycloak'] = {
            'auth': {
                'existingSecret': keycloak_secret.name
            },
            'postgresql': {
                'auth': {
                    'existingSecret': keycloak_postgresql_secret.name
                },
                'existingSecret': keycloak_postgresql_secret.name
            }
        }
    else:
        install_file['global']['keycloak']['authURL'] = sanitize_auth_url(keycloak_auth_url)
        install_file['keycloak'] = {'enabled': False}
        install_file['keycloak-config-cli'] = {'enabled': True}

    if ingress_certmanager_disabled:
        install_file['global']['ingress']['certmanager'] = False

    if use_tls_secret:
        install_file['global']['ingress']['tlsSecret'] = ingress_cert_secret_object.name

    if license_as_env_var:
        install_file['global']['license']['asFile'] = False

    if license_on_demand:
        install_file['global']['license']['onDemand'] = True
        install_file['kxi-acc-svc'] = {'enabled': False}

    if os.path.exists(output_file):
        if not click.confirm(phrases.values_file_overwrite.format(output_file=output_file)):
            output_file = click.prompt(phrases.values_save_path)

    with open(output_file, 'w') as f:
        yaml.dump(install_file, f)

    click.secho(phrases.footer_setup, bold=True)
    click.echo(phrases.values_file_saved.format(output_file=output_file))

    return output_file, chart_repo_name


@install.command(aliases=['install'])
@arg.install_setup_group
@arg.output_file()
@arg.filepath()
@arg.release()
@arg.version()
@arg.operator_version()
@arg.force()
@arg.import_users()
@arg.chart()
@click.pass_context
def run(ctx, namespace, chart_repo_name, chart_repo_url, chart_repo_username, 
          license_secret, license_as_env_var, license_filepath,
          client_cert_secret, image_repo, image_repo_user, image_pull_secret, gui_client_secret, operator_client_secret,
          keycloak_secret, keycloak_postgresql_secret, keycloak_auth_url, hostname, 
          ingress_cert_secret, ingress_cert, ingress_key,
          output_file, filepath, release, version, operator_version, force, import_users, chart):
    """Install kdb Insights Enterprise with a values file"""

    # Run setup prompts if necessary
    if filepath is None:
        click.echo(phrases.header_run)
        filepath, chart_repo_name = ctx.forward(setup)

    filepath, namespace, chart_repo_url, image_pull_secret, license_secret = get_values_and_secrets(filepath,
        namespace, release, chart_repo_url,
        image_pull_secret, license_secret)

    insights_chart = parse_chart_cli_params(chart, chart_repo_name, chart_repo_url)

    docker_config = get_docker_config_secret(namespace, image_pull_secret, DOCKER_SECRET_KEY)

    if is_valid_upgrade_version(release, namespace, version):
        if click.confirm(f'Would you like to upgrade to version {version}?'):
            return perform_upgrade(namespace, release, insights_chart, None, version, operator_version, image_pull_secret,
                    license_secret, filepath, import_users, docker_config, force)
        else:
            return

    install_operator, is_op_upgrade, operator_version, operator_release, crd_data = check_for_operator_install(release,
        insights_chart, version, operator_version, docker_config, force)

    install_operator_and_release(release, namespace, version, operator_version, operator_release, filepath,
                                 image_pull_secret, license_secret, insights_chart, import_users, docker_config,
                                 install_operator, is_op_upgrade, crd_data, is_upgrade=False)

@install.command()
@arg.namespace()
@arg.release()
@arg.chart_repo_name(hidden=True)
@arg.chart_repo_url()
@arg.assembly_backup_filepath()
@arg.version()
@arg.operator_version()
@arg.image_pull_secret()
@arg.license_secret()
@arg.filepath()
@arg.force()
@arg.import_users()
@arg.chart()
def upgrade(namespace, release, chart_repo_name, chart_repo_url, assembly_backup_filepath, version, operator_version, image_pull_secret,
            license_secret, filepath, force, import_users, chart):
    """Upgrade kdb Insights Enterprise"""
    click.secho(phrases.header_upgrade, bold=True)

    filepath, namespace, chart_repo_url, image_pull_secret, license_secret = get_values_and_secrets(filepath,
        namespace, release, chart_repo_url,
        image_pull_secret, license_secret)

    insights_chart = parse_chart_cli_params(chart, chart_repo_name, chart_repo_url)

    is_valid_upgrade_version(release, namespace, version)

    docker_config = get_docker_config_secret(namespace, image_pull_secret, DOCKER_SECRET_KEY)

    perform_upgrade(namespace, release, insights_chart, assembly_backup_filepath, version, operator_version, image_pull_secret,
                    license_secret, filepath, import_users, docker_config, force)


def parse_chart_cli_params(
    chart: str,
    chart_repo_name: str | None,
    chart_repo_url: str | None
) -> helm_chart.Chart:
    # chart-repo-name or chart-repo-url takes precedence over 'chart' arg to prevent breaking change
    if chart_repo_name:
        chart = f"{chart_repo_name}/insights"
    elif chart_repo_url:
        chart = f"{chart_repo_url}/insights"
    insights_chart = helm_chart.Chart(chart)

    return insights_chart


def perform_upgrade(namespace, release, chart, assembly_backup_filepath, version, operator_version, image_pull_secret,
                    license_secret, filepath, import_users, docker_config, force):

    upgraded = False

    install_operator, is_op_upgrade, operator_version, operator_release, crd_data = check_for_operator_install(release,
        chart, version, operator_version, docker_config, force)

    if not insights_installed(release, namespace):
        click.echo(phrases.upgrade_skip_to_install)
        if filepath is None:
            raise ClickException(phrases.values_filepath_missing)

        install_operator_and_release(release, namespace, version, operator_version, operator_release,
                                 filepath, image_pull_secret, license_secret,
                                 chart, import_users, docker_config, install_operator,
                                 is_op_upgrade, crd_data, is_upgrade=False)
        click.secho(str.format(phrases.upgrade_complete, version=version), bold=True)
        return

    deleted, assembly_backup_filepath = teardown_assemblies(namespace, assembly_backup_filepath, force, phrases.upgrade_asm_persist)
    if all(deleted):
        click.secho(phrases.upgrade_insights, bold=True)
        upgraded =  install_operator_and_release(release, namespace, version, operator_version, operator_release, 
                                                filepath, image_pull_secret, license_secret, 
                                                chart, import_users, docker_config, install_operator, 
                                                is_op_upgrade, crd_data, is_upgrade=True)

    reapply_assemblies(assembly_backup_filepath, namespace, deleted)

    if upgraded:
        click.secho(str.format(phrases.upgrade_complete, version=version), bold=True)


@install.command(aliases=['uninstall'])
@arg.release()
@arg.namespace()
@arg.force()
@click.option('--uninstall-operator', is_flag=True, help='Remove KXI Operator installation')
@arg.assembly_backup_filepath()
def delete(release, namespace, force, uninstall_operator, assembly_backup_filepath):
    """Uninstall kdb Insights Enterprise"""
    namespace = options.namespace.prompt(namespace)    
    delete_release_operator_and_crds(release=release,
                                     namespace=namespace,
                                     force=force,
                                     uninstall_operator=uninstall_operator,
                                     assembly_backup_filepath=assembly_backup_filepath
                                     )


@install.command()
@arg.chart_repo_name()
def list_versions(chart_repo_name):
    """
    List available versions of kdb Insights Enterprise
    """
    helm.list_versions(options.chart_repo_name.prompt(chart_repo_name, silent=True))


@install.command()
@arg.namespace()
@arg.release()
def get_values(namespace, release):
    """
    Display the values of the currently deployed kdb Insights Enterprise
    """
    log.debug(f"Getting Helm values from release {release} in namespace {namespace}")
    try:
        vals = helm.get_values(release, namespace)
    except subprocess.CalledProcessError as e:
        helm_error = e.stderr.strip('\n')
        error = phrases.helm_get_values_fail.format(release=release, namespace=namespace, helm_error=helm_error)
        raise click.ClickException(error)

    click.echo(yaml.safe_dump(vals))


def get_values_and_secrets(
    filepath,
    namespace,
    release,
    chart_repo_url,
    image_pull_secret,
    license_secret
    ):

    namespace = options.namespace.prompt(namespace)

    if filepath:
        values_dict = load_values_stores(filepath)
    else:
        try:
            values_dict = helm.get_values(release, namespace)
        except subprocess.CalledProcessError:
            values_dict = {}

    chart_repo_url = check_azure_oci_repo(values_dict, chart_repo_url)

    image_pull_secret, license_secret = get_image_and_license_secret_from_values(values_dict, image_pull_secret, license_secret)

    validate_values(namespace, values_dict)

    return filepath, namespace, chart_repo_url, image_pull_secret, license_secret


def check_azure_oci_repo(values_dict, chart_repo_url):
    ctx = click.get_current_context()
    if chart_repo_url or ctx.parent.info_name != 'azure':
        return chart_repo_url
    global_image_repository: str = values_dict['global']['image']['repository']
    # we only need the first part of the url
    return f'oci://{global_image_repository.split("/")[0]}'

def get_secret(secret_object: secret.Secret,
               secret_data_name: str
    ):
    """
    Return decoded secret
    """
    secret_value = secret_object.read()
    if secret_value:
        try:
            secret_value = base64.b64decode(secret_value.data[secret_data_name]).decode('ascii')
        except KeyError:
            log.error(f'Cannot find key {secret_data_name} in secret {secret_object.name}')
            return None
    else:
        log.debug(f'Cannot find values secret {secret_object.name}')

    return secret_value


def get_minor_version(version):
    if version:
        version_parsed = version.split(".")
        return version_parsed[0] + "." + version_parsed[1]


def get_operator_version(
    chart: helm_chart.Chart,
    insights_version: str,
    operator_version: str
):
    """Determine operator version to use. Retrieve the most recent operator minor version matching the insights version"""
    if operator_version is None:
        operator_version = filter_max_operator_version(
                                available_operator_versions(chart),
                                insights_version
                        )
    return operator_version


def available_operator_versions(chart: helm_chart.Chart) -> list[str]:
    if chart.is_remote:
        return helm.get_operator_versions(chart)
    else:
        return local_operator_versions(chart)


def local_operator_versions(
    chart: helm_chart.Chart,
    prefix: str = 'kxi-operator-',
    suffix: str = '.tgz',
) -> list[str]:
    # In order to identify operator versions we currently look for 'kxi-operator-*.tgz'
    # in the same folder as the Insights chart and parse the version out of the filename.

    # This isn't foolproof, helm doesn't actually care about the filename at install time,
    # it reads the version out of the Chart.yaml. However parsing the version is sufficient for
    # the majority of circumstances since the tgz will be downloaded via 'helm fetch' which follows
    # the naming convention of {chart}-{version}.tgz
    parent = Path(chart.full_ref).parent
    versions = []
    glob = f"{prefix}*{suffix}"
    log.debug(f"Searching {parent} for charts matching glob {glob}")
    for tgz_file in parent.glob(glob):
        versions.append(tgz_file.name.lstrip(prefix).rstrip(suffix))
    return versions


def filter_max_operator_version(
    versions: list[str],
    insights_version: str,
) -> Optional[str]:
    regex = '-rc.[0-9]+$' if '-rc.' in insights_version else ''
    matching_versions = []
    minor_version = get_minor_version(insights_version)
    for version in versions:
        if re.search(regex, version) and version.startswith(minor_version):
            matching_versions.append(version)
    if matching_versions == []:
        log.warn(f'Cannot find operator version to install matching insights minor version {insights_version}')
        return None
    else:
        return str(max(map(semver.VersionInfo.parse, matching_versions)))


def sanitize_ingress_host(raw_string):
    """Sanitize a host name to allow it to be used"""
    return raw_string.replace('http://', '').replace('https://', '')


def sanitize_auth_url(raw_string):
    """Sanitize a Keycloak auth url to allow it to be used"""
    trimmed = raw_string.strip()

    if trimmed.startswith('https://'):
        click.echo('Replacing https:// with http:// in --keycloak-auth-url')
        trimmed = f"http://{trimmed.replace('https://', '')}"

    if not trimmed.startswith('http://'):
        trimmed = f'http://{trimmed}'

    if not trimmed.endswith('/'):
        trimmed = f'{trimmed}/'

    return trimmed


def prompt_for_license(secret: secret.Secret, filepath, license_as_env_var):
    """Prompt for an existing license or create on if it doesn't exist"""
    license_on_demand = False

    exists, is_valid, _ = secret.validate()
    if not exists:
        secret, license_on_demand = populate_license_secret(secret, filepath=filepath, as_env=license_as_env_var)
        secret.create()
    elif not is_valid:
        if click.confirm(phrases.secret_exist_invalid.format(name=secret.name)):
            click.echo(phrases.secret_overwriting.format(name=secret.name))
            secret, license_on_demand = populate_license_secret(secret, filepath=filepath, as_env=license_as_env_var)
            secret.patch()
    else:
        click.echo(phrases.secret_use_existing.format(name=secret.name))
    return secret, license_on_demand


def ensure_secret(secret: secret.Secret, populate_function: Callable, data = None):
    exists, is_valid, _ = secret.validate()
    if not exists:
        secret = populate_function(secret, data=data)
        secret.create()
    elif not is_valid:
        if click.confirm(phrases.secret_exist_invalid.format(name=secret.name)):
            click.echo(phrases.secret_overwriting.format(name=secret.name))
            secret = populate_function(secret, data=data)
            secret.patch()
    else:
        click.echo(phrases.secret_use_existing.format(name=secret.name))
    return secret


def populate_cert(secret: secret.Secret, **kwargs):
    """Populates a certificate secret with a cert and key"""
    key = gen_private_key()
    cert = gen_cert(key)
    return populate_tls_secret(secret, cert, key)


def prompt_for_image_details(secret: secret.Secret, image_repo, image_repo_user):
    """Prompt for an existing image pull secret or create on if it doesn't exist"""
    image_repo = options.image_repo.prompt(image_repo)
    secret = ensure_secret(secret, populate_image_pull_secret, {'image_repo': image_repo, 'image_repo_user': image_repo_user})
    return image_repo, secret


def populate_image_pull_secret(secret: secret.Secret, **kwargs):
    data = kwargs.get('data')
    image_repo = data['image_repo']
    image_repo_user = data['image_repo_user']
    existing_config = check_existing_docker_config(image_repo, DOCKER_CONFIG_FILE_PATH)

    if existing_config and not image_repo_user and not options.image_repo_password.click_option_kwargs.get('default')():
        # parse the user from the existing config which is a base64 encoded string of "username:password"
        user = base64.b64decode(existing_config['auth']).decode('ascii').split(':')[0]
        if click.confirm(
                phrases.image_creds.format(user=user, repo=image_repo, config=DOCKER_CONFIG_FILE_PATH)):
            docker_config = {
                'auths': {
                    image_repo: existing_config
                }
            }
            secret = populate_docker_config_secret(secret, docker_config)
            return secret

    user = options.image_repo_user.prompt(image_repo_user, prompt_message=phrases.image_user.format(repo=image_repo))
    password = options.image_repo_password.prompt(prompt_message=phrases.image_password.format(user=user))
    docker_config = create_docker_config(image_repo, user, password)
    secret = populate_docker_config_secret(secret, docker_config)

    return secret


def populate_keycloak_secret(secret: secret.Secret, **kwargs):
    admin_password = options.keycloak_admin_password.prompt()
    management_password = options.keycloak_management_password.prompt()

    secret.data = {
            'admin-password': base64.b64encode(admin_password.encode()).decode('ascii'),
            'management-password': base64.b64encode(management_password.encode()).decode('ascii')
        }

    return secret


def populate_postgresql_secret(secret: secret.Secret, **kwargs):
    postgresql_postgres_password = options.postgresql_postgres_password.prompt()
    postgresql_password = options.postgresql_user_password.prompt()

    secret.data = {
            'postgresql-postgres-password': base64.b64encode(postgresql_postgres_password.encode()).decode('ascii'),
            'postgres-password': base64.b64encode(postgresql_postgres_password.encode()).decode('ascii'),
            'postgresql-password': base64.b64encode(postgresql_password.encode()).decode('ascii'),
            'password': base64.b64encode(postgresql_password.encode()).decode('ascii')
        }

    return secret


def prompt_for_ingress_cert(secret: secret.Secret, name, ingress_cert, ingress_key, ingress_certmanager_disabled):
    use_tls_secret = False
    if name or ingress_cert or ingress_key:
        use_tls_secret = True
        ingress_certmanager_disabled = True
        secret = ensure_secret(secret, populate_ingress_cert,
            {
                'ingress_cert':ingress_cert, 
                'ingress_key': ingress_key
            }
        )
    elif not ingress_certmanager_disabled:
        click.echo(phrases.ingress_lets_encrypt)


    return ingress_certmanager_disabled, use_tls_secret, secret


def populate_ingress_cert(secret: secret.Secret, **kwargs):
    path_to_cert = options.ingress_cert.prompt(kwargs.get('data')['ingress_cert'])
    with open(path_to_cert, 'r') as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data.encode(), backend=default_backend())

    path_to_key = options.ingress_key.prompt(kwargs.get('data')['ingress_key'])
    with open(path_to_key, 'r') as key_file:
        key_data = key_file.read()
        key = serialization.load_pem_private_key(key_data.encode(), password=None, backend=default_backend())

    return populate_tls_secret(secret, cert, key)


def create_docker_config(image_repo, user, password):
    """Output the .dockerconfigjson format given a repo, username and password"""
    config = {
        'auths': {
            image_repo: {
                'username': user,
                'password': password,
                'auth': base64.b64encode(f'{user}:{password}'.encode()).decode('ascii')
            }
        }
    }

    return config


def check_existing_docker_config(image_repo, file_path):
    """Check local .docker/config.json for repo credentials"""
    log.debug(f'Checking {file_path} for existing credentials for the repository {image_repo}')
    try:
        with open(file_path, 'r') as f:
            config = json.loads(f.read())
        if 'auths' in config and image_repo in config['auths']:
            return config['auths'][image_repo]
    except FileNotFoundError:
        pass

    return None


def populate_license_secret(secret: secret.Secret, filepath = None, as_env = False):
    """Populate the data in a license secret"""
    license_on_demand = False

    filepath = options.license_filepath.prompt(filepath)

    if os.path.basename(filepath) == 'kc.lic':
        license_on_demand = True

    with open(filepath, 'rb') as license_file:
        encoded_license = base64.b64encode(license_file.read())

    license_data = {
        'license': encoded_license.decode('ascii')
    }

    if as_env:
        secret.string_data = license_data
    else:
        secret.data = license_data

    return secret, license_on_demand


def populate_docker_config_secret(secret: secret.Secret, docker_config):
    """Populate a secret with a docker config file"""
    docker_config = json.dumps(docker_config).encode()
    secret.data = {
        DOCKER_SECRET_KEY: base64.b64encode(docker_config).decode('ascii')
    }
    return secret

def get_docker_config_secret(
        namespace: str,
        secret_name: str,
        secret_data_name: str = DOCKER_SECRET_KEY
) -> str:
    s = secret.Secret(namespace, secret_name)
    docker_config = get_secret(s, secret_data_name)
    if docker_config is not None:
        return docker_config
    else:
        raise click.ClickException('Docker config secret not found in Cluster')

def populate_tls_secret(secret: secret.Secret, cert, key):
    """Create a TLS secret in a given namespace from a cert and private key"""

    # the private key must be unencrypted for a k8s secret
    key_string = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_string = cert.public_bytes(serialization.Encoding.PEM)

    secret.data = {
        TLS_KEY: base64.b64encode(key_string).decode('ascii'),
        TLS_CRT: base64.b64encode(cert_string).decode('ascii')
    }

    return secret

def get_image_and_license_secret_from_values(values_dict, image_pull_secret, license_secret):
    """Read image_pull_secret and license_secret from argument, values file, default"""
    if image_pull_secret is None:
        image_pull_secret = get_from_values_store(
                                ['global', 'imagePullSecrets', 0, 'name'],
                                values_dict,
                                default_val(image_pull_key)
                                )

    if license_secret is None:
        license_secret = get_from_values_store(
                                ['global', 'license', 'secretName'],
                                values_dict,
                                default_val(license_key)
                                )

    return image_pull_secret, license_secret

def load_values_stores(values_file):
    values_file_dict = {}
    if values_file:
        if not os.path.exists(values_file):
            raise click.ClickException(f'File not found: {values_file}. Exiting')
        else:
            with open(values_file) as f:
                try:
                    values_file_dict = yaml.safe_load(f)
                except yaml.YAMLError:
                    raise click.ClickException(f'Invalid values file {values_file}')

    return values_file_dict

def get_from_values_store(key, values_dict, default):
    try:
        val = values_dict
        for k in key:
            val = val[k]
        log.debug(f'Using key {key} in values')
    except KeyError:
        log.debug(f'Cannot find key {key} in values. Using default {default}')
        val = default
    except BaseException:
        raise click.ClickException(f'Invalid values')

    return val


def gen_private_key():
    """Creates a basic private key"""
    log.debug('Generating private key with size 2048 and exponent 65537')

    private_key = asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key


def gen_cert(private_key):
    """Creates a basic certificate given a public key"""
    log.debug('Generating cert with common name insights.kx.com')

    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'insights.kx.com')])

    # For a self-signed cert, the subject and the issuer are always the same
    builder = x509.CertificateBuilder(
        issuer_name=subject,
        subject_name=subject,
        public_key=private_key.public_key(),
        serial_number=x509.random_serial_number(),
        not_valid_before=datetime.datetime.utcnow(),
        not_valid_after=datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    )

    # This must be set on the generated cert in order of it to be a valid Issuer in kubernetes
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
                                    critical=False)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)

    return builder.sign(private_key, hashes.SHA256(), default_backend())


def check_for_operator_install(release, chart: helm_chart.Chart, insights_ver, op_ver, docker_config='', force=False):
    """
    Determine if the operator needs to be install or upgraded
    Fetch the CRD data if it's an upgrade
    This all happens prior to install / upgrade so we can exit cleanly in the event of an exception
    """
    installed_operator_version = None
    operator_installed_charts, operator_installed_releases = get_installed_operator_versions(operator_namespace)
    is_upgrade = len(operator_installed_charts) > 0

    if is_upgrade:
        installed_operator_version = operator_installed_charts[0]
        release = operator_installed_releases[0]
        click.echo(f'kxi-operator already installed with version {installed_operator_version}')

    insights_version_minor = get_minor_version(insights_ver)
    operator_version_to_install = get_operator_version(chart, insights_ver, op_ver)
    installed_operator_compatible = insights_version_minor == get_minor_version(installed_operator_version)
    operator_version_to_install_compatible = insights_version_minor == get_minor_version(operator_version_to_install)

    if is_upgrade and not release:
        log.warn('kxi-operator already installed, but not managed by helm')
        if installed_operator_compatible:
            click.echo(f'Not installing kxi-operator')
            return False, False, None, None, []
        else:
            raise ClickException(f'Installed kxi-operator version {installed_operator_version} is incompatible with insights version {insights_ver}')

    if op_ver and not operator_version_to_install_compatible:
        raise ClickException(f'kxi-operator version {op_ver} is incompatible with insights version {insights_ver}')

    if not installed_operator_compatible and not operator_version_to_install_compatible: 
        raise ClickException('Compatible version of operator not found')

    if operator_version_to_install:
        install_operator = force or op_ver is not None or click.confirm(f'Do you want to install kxi-operator version {operator_version_to_install}?', default=True)
    else:
        click.echo(f'Not installing kxi-operator')
        install_operator = False

    crd_data = []
    if install_operator and is_upgrade:
        check_upgrade_version(installed_operator_version, operator_version_to_install)
        crd_data = get_crd_data(chart, operator_version_to_install, docker_config)

    return install_operator, is_upgrade, operator_version_to_install, release, crd_data

def get_crd_data(
    insights_chart: helm_chart.Chart,
    operator_version: str,
    docker_config: str = ''
):
    if insights_chart.is_remote:
        cache = helm.get_repository_cache()
        helm.fetch(insights_chart.repo_name, 'kxi-operator', cache, operator_version, docker_config)
        crd_data = read_cached_crd_files(operator_version, Path(cache))
    else:
        # Assumes that the operator is in the same folder as the Insights chart
        # with a naming convention parent/kxi-operator-{version}.tgz
        crd_data = read_cached_crd_files(operator_version, Path(insights_chart.full_ref).parent)
    return crd_data

def install_operator_and_release(
    release,
    namespace,
    version,
    operator_version,
    operator_release,
    values_file,
    image_pull_secret,
    license_secret,
    chart,
    import_users,
    docker_config,
    install_operator = True,
    is_operator_upgrade = False,
    crd_data = [],
    is_upgrade = None
):
    """Install operator and insights"""

    # Check if keycloak users are to be imported
    # On install if import_users is unset or True we import
    # On upgrade only import users if import_users flag is set to True
    # Never import if import_users flag is set to False
    if ((import_users == None) and (not is_upgrade)) or import_users == True:
        args = ['--set', 'keycloak.importUsers=true']
    else:
        args = ['--set', 'keycloak.importUsers=false']

    existing_values = None

    if install_operator:
        create_namespace(operator_namespace)

        copy_secret(image_pull_secret, namespace, operator_namespace)
        copy_secret(license_secret, namespace, operator_namespace)

        if is_upgrade and values_file is None:
            existing_values = yaml.safe_dump(helm.get_values(operator_release, operator_namespace))

        operator_full_ref = get_operator_location(chart, operator_version)
        helm.upgrade_install(operator_release, chart=operator_full_ref, values_file=values_file,
                     version=operator_version, namespace=operator_namespace, args = [], docker_config=docker_config, existing_values=existing_values)

        if is_operator_upgrade:
            replace_chart_crds(crd_data)

    if is_upgrade and values_file is None:
        existing_values = yaml.safe_dump(helm.get_values(release, namespace))

    helm.upgrade_install(release, chart=chart.full_ref, values_file=values_file,
                 args=args, version=version, namespace=namespace, docker_config=docker_config, existing_values=existing_values)

    return True

def get_operator_location(
    insights_chart: helm_chart.Chart,
    operator_version: str,
    chart_name: str = 'kxi-operator',
) -> str:
    if insights_chart.is_remote:
        operator = f'{insights_chart.repo_name}/{chart_name}'
    else:
        # For local install, we only support find the operator in the same folder as the Insights
        # chart with the naming convention kxi-operator-{version}.tgz currently
        operator = str(Path(insights_chart.full_ref).parent / f'{chart_name}-{operator_version}.tgz')

    return operator

def delete_release_operator_and_crds(release, namespace, force, uninstall_operator, assembly_backup_filepath):
    """Delete insights, operator and CRDs"""
    common.load_kube_config()
    
    if not insights_installed(release, namespace):
        click.echo('\nkdb Insights Enterprise installation not found')
    elif force or click.confirm('\nkdb Insights Enterprise is deployed. Do you want to uninstall?'):
        assembly.backup_assemblies(namespace, assembly_backup_filepath, force)
        assembly.delete_running_assemblies(namespace, True, True)
        helm.uninstall(release=release, namespace=namespace)

    if not (force or uninstall_operator):
        return

    crds = common.get_existing_crds(CRD_NAMES)
    for i in crds:
        try:
            common.delete_crd(i)
        except click.ClickException as e:
            log.error(e)

    _, operator_releases = get_installed_operator_versions(operator_namespace)

    if len(operator_releases)>0:
        helm.uninstall(release=operator_releases[0], namespace=operator_namespace)
    else:
        click.echo(f'\nkdb Insights Enterprise kxi-operator not found')


def copy_secret(name, from_ns, to_ns):
    common.load_kube_config()
    api = k8s.client.CoreV1Api()
    try:
        secret = api.read_namespaced_secret(namespace=from_ns, name=name)
    except k8s.client.rest.ApiException as exception:
        raise click.ClickException(f'Exception when trying to get secret {exception}')

    secret.metadata = k8s.client.V1ObjectMeta(namespace=to_ns, name=name)

    try:
        secret = api.create_namespaced_secret(namespace=to_ns, body=secret)
    except k8s.client.rest.ApiException as exception:
        if not exception.status == 409:
            raise click.ClickException(f'Exception when trying to create secret {exception}')


def insights_installed(release, namespace):
    """Check if a helm release of insights exists"""
    return len(get_installed_charts(release, namespace)) > 0


def get_installed_charts(release, namespace):
    """Retrieve running helm charts"""
    base_command = ['helm', 'list', '--filter', "^"+release+"$", '-o', 'json','--namespace', namespace]
    try:
        log.debug(f'List command {base_command}')
        l = subprocess.check_output(base_command)
        return json.loads(l)
    except subprocess.CalledProcessError as e:
        click.echo(e)


def get_installed_operator_versions(namespace: str = operator_namespace):
    """Retrieve running operator versions"""
    api_instance = k8s.client.AppsV1Api(k8s.client.ApiClient())
    operators = api_instance.list_namespaced_deployment(namespace, label_selector='app.kubernetes.io/name=kxi-operator')
    operator_versions = []
    operator_releases = []
    for item in operators.items:
        operator_versions.append(item.metadata.labels.get("helm.sh/chart").lstrip("kxi-operator-"))
        operator_releases.append(item.metadata.labels.get(operator_release_name))
    return (operator_versions, operator_releases)

# Check if Keycloak is being deployed with Insights
def deploy_keycloak():
    return '--keycloak-auth-url' not in sys.argv


# Structure of the config:
#   name: (key in values file, secret type, required keys, mandatory)
def get_secret_config():
    return {
        license_key: (['global', 'license', 'secretName'], SECRET_TYPE_OPAQUE, LICENSE_KEYS, True),
        'client.cert.secret': (['global', 'caIssuer', 'secretName'],  SECRET_TYPE_TLS, CLIENT_CERT_KEYS, True),
        image_pull_key: (['global', 'imagePullSecrets', 0, 'name'], SECRET_TYPE_DOCKERCONFIG_JSON, IMAGE_PULL_KEYS, True),
        'keycloak.secret': (['keycloak', 'auth', 'existingSecret'], SECRET_TYPE_OPAQUE, KEYCLOAK_KEYS, deploy_keycloak()),
        'keycloak.postgresqlSecret': (['keycloak', 'postgresql', 'existingSecret'], SECRET_TYPE_OPAQUE, POSTGRESQL_KEYS, deploy_keycloak()),
        'ingress.cert.secret': (['global', 'ingress', 'tlsSecret'], SECRET_TYPE_TLS, INGRESS_CERT_KEYS, False)
    }


def validate_values(namespace, values_dict):
    click.echo(phrases.values_validating)

    exit_execution = False
    for k, v in get_secret_config().items():
        # if the secret is mandatory, validate it
        if v[3]:
            default = default_val(k)
            name = get_from_values_store(v[0], values_dict, default)
            exists, is_valid, _ = secret.Secret(namespace, name, v[1], v[2]).validate()
            if not exists:
                log.error(phrases.secret_validation_not_exist.format(name=name))
                exit_execution = True
            elif not is_valid:
                log.error(phrases.secret_validation_invalid.format(name=name, type=v[1], keys=v[2]))
                exit_execution = True
    if exit_execution:
        raise click.ClickException(phrases.values_validation_fail)
    click.echo('')


def lookup_secret(namespace, arg, values_file, default_key):
    values_file_dict = load_values_stores(values_file)

    # lookup the secret configuration in the config
    v = get_secret_config()[default_key]

    # if the name isn't passed as an argument, look it up in the values stores
    if arg is None:
        log.debug(f'No command line argument passed for {default_key}, looking up in values stores')
        arg = get_from_values_store(v[0], values_file_dict, default_val(default_key))

    s = secret.Secret(namespace, arg, v[1], v[2])
    return s

def read_cached_crd_files(
    version: str,
    folder_parent: Path,
    chart_name: str = 'kxi-operator',
    crds: list = CRD_FILES
):
    crd_data = []
    tar_path = folder_parent / f'{chart_name}-{version}.tgz'

    click.echo(f'Reading CRD data from {tar_path}')
    # expect the files to exist in the chart tgz inside the crds folder
    files = [f'{chart_name}/crds/{crd}' for crd in crds]
    raw_data = common.extract_files_from_tar(tar_path, files)
    for blob in raw_data:
        try:
            crd_data.append(yaml.safe_load(blob))
        except yaml.YAMLError as e:
            raise click.ClickException(f'Failed to parse custom resource definition file: {e}')

    return crd_data

def replace_chart_crds(crd_data):
    for body in crd_data:
        common.replace_crd(body['metadata']['name'], body)

@install.command()
@click.argument('insights_revision', default=None, required = False)
@arg.release()
@arg.operator_revision()
@arg.image_pull_secret()
@arg.namespace()
@arg.force()
@arg.assembly_backup_filepath()
@arg.chart_repo_name()
def rollback(insights_revision, release, operator_revision, namespace, image_pull_secret, force, assembly_backup_filepath, chart_repo_name):
    common.load_kube_config()
    argo_managed_operator = False
    current_operator_version, current_operator_release  = get_installed_operator_versions(operator_namespace)
    insights_history,operator_history = helm.history(release, 'json', None, current_operator_version, current_operator_release[0])

    if insights_history == []:
        raise click.ClickException(f'Cannot find a release history of: {release}')

    if operator_history == []:
        if current_operator_version == [] or operator_revision is not None:
            raise click.ClickException(f'Cannot find an operator release history')
        else:
            argo_managed_operator = True

    # Get the rollback base command for insights
    base_command,insights_rollback_version,insights_revision = insights_rollback(release, insights_history, insights_revision)

    # Get the rollback base command for operator
    operator_details,base_command_operator = rollback_operator(operator_revision, argo_managed_operator, operator_history, current_operator_release, insights_rollback_version, insights_revision, current_operator_version, force)

    # Teardown assemblies
    deleted,assembly_backup_filepath  = teardown_assemblies(namespace, assembly_backup_filepath, force, phrases.rollback_asm_persist)

    if operator_details[0] is not None:
        # Rollback  operator
        try_rollback(base_command_operator, 'Rollback kxi-operator complete for version ' + operator_details[1])
        # Replace crds
        replace_crds(image_pull_secret, namespace, operator_details, chart_repo_name)

    click.secho(phrases.rollback_start, bold=True)
    try_rollback(base_command, 'Rollback kdb Insights Enterprise complete for version ' + insights_rollback_version)

    reapply_assemblies(assembly_backup_filepath, namespace, deleted)

def insights_rollback(release, insights_history, insights_revision):
    if insights_revision is None:
        base_command = ['helm', 'rollback', release]
        insights_revision = insights_history[len(insights_history)-2]['revision']
        insights_rollback_version = insights_history[len(insights_history)-2]['app_version']
    else:
        base_command = ['helm', 'rollback', release, insights_revision]
        try:
            insights_rollback_version = next(entry['app_version'] for entry in insights_history if entry['revision'] == int(insights_revision))
        except StopIteration:
            raise click.ClickException(f'Could not find revision {insights_revision} in history')

    return base_command,insights_rollback_version,insights_revision

def rollback_operator(operator_revision, argo_managed_operator, operator_history, current_operator_release, insights_rollback_version, insights_revision, current_operator_version, force):
    if operator_revision is not None and not argo_managed_operator:
        try:
            operator_details = (operator_revision, next(entry['app_version'] for entry in operator_history if entry['revision'] == int(operator_revision)))
        except StopIteration:
            raise click.ClickException(f'Could not find revision {operator_revision} in kxi-operator history')
        base_command_operator = ['helm', 'rollback', current_operator_release[0], operator_details[0], '--namespace', 'kxi-operator']
        check_operator_rollback_version(insights_rollback_version, operator_details[1])
        click.echo(phrases.rollback_insights_operator.format(insights_version=insights_rollback_version, revision=insights_revision, operator_version=operator_details[1], operator_revision=operator_details[0]))
        if not force and not click.confirm('Proceed?'):
            return sys.exit(0)
    else:
        check_operator_rollback_version(insights_rollback_version, current_operator_version[0])
        operator_details = (None, None)
        base_command_operator = None
        click.echo(phrases.rollback_insights.format(insights_version=insights_rollback_version, revision=insights_revision, operator_version=current_operator_version[0]))
        if not force and not click.confirm('Proceed?'):
                return sys.exit(0)

    return operator_details,base_command_operator

def operator_rollback_version(operator_history, rollback_version,  current_version):
    operator_version_minor = get_minor_version(rollback_version)
    current_version_op = get_minor_version(current_version)
    data = [d for d in operator_history if d['app_version'].startswith(operator_version_minor)]
    if len(data) == 1 and current_version_op == operator_version_minor:
        return (None ,current_version_op) 
    else:
        return (str(data[len(data)-2]['revision']),data[len(data)-2]['app_version'])
    
def try_rollback(base_command, phrase):
    try:
        log.debug(f'List command {base_command}')
        subprocess.check_output(base_command)
        click.secho(phrase, bold=True)
    except subprocess.CalledProcessError as e:
        raise click.ClickException(e)

@install.command()
@arg.release()
@arg.operator_history()
def history(release, show_operator):
    """
    List the revision history of a kdb Insights Enterprise install
    """
    common.load_kube_config()    
    current_operator_version, current_operator_release  = get_installed_operator_versions(operator_namespace)
    helm.history(options.chart_repo_name.prompt(release, silent=True), None, show_operator, current_operator_version, current_operator_release[0])

def check_operator_rollback_version(from_version, to_version):
    v1 = semver.VersionInfo.parse(from_version)
    v2 = semver.VersionInfo.parse(to_version)
    if v1.major != v2.major or  v1.minor != v2.minor:
        raise click.ClickException(f'Insights rollback target version {from_version} is incompatible with target operator version {to_version}. Minor versions must match.')

def check_upgrade_version(from_version, to_version):
    v1 = semver.VersionInfo.parse(from_version)
    v2 = semver.VersionInfo.parse(to_version)
    if v1 > v2:
        raise click.ClickException(f'Cannot upgrade from version {from_version} to version {to_version}. Target version must be higher than currently installed version.')

def is_valid_upgrade_version(release, namespace, version):
    insights_installed_charts = get_installed_charts(release, namespace)
    if len(insights_installed_charts) > 0:
        insights_installed_version = insights_installed_charts[0]["app_version"]
        click.echo(f'kdb Insights Enterprise is already installed with version {insights_installed_version}')
        check_upgrade_version(insights_installed_version, version)
        return True
    else:
        return False

def teardown_assemblies(namespace, assembly_backup_filepath, force, phrase):
    click.secho(phrases.upgrade_asm_backup, bold=True)
    assembly_backup_filepath = assembly.backup_assemblies(namespace, assembly_backup_filepath, force)
    # Teardown Assemblies
    click.secho(phrases.upgrade_asm_teardown, bold=True)
    click.secho(phrase)
    deleted = assembly.delete_running_assemblies(namespace=namespace, wait=True, force=force)
    return (deleted, assembly_backup_filepath)

def reapply_assemblies(assembly_backup_filepath, namespace, deleted):
    click.secho(phrases.upgrade_asm_reapply, bold=True)
    if deleted and assembly_backup_filepath and all(assembly.create_assemblies_from_file(
                                            namespace=namespace, filepath=assembly_backup_filepath, use_kubeconfig=True
                                            )
                                        ):
        os.remove(assembly_backup_filepath)

def replace_crds(image_pull_secret, namespace, operator_details, chart_repo_name):
    crd_data = []
    image_pull_secret = options.image_pull_secret.prompt(image_pull_secret)
    docker_config = get_docker_config_secret(namespace, image_pull_secret, DOCKER_SECRET_KEY)
    cache = helm.get_repository_cache()
    helm.fetch(chart_repo_name, 'kxi-operator', cache,  operator_details[1], docker_config)
    crd_data = read_cached_crd_files(operator_details[1], Path(cache))
    replace_chart_crds(crd_data)
