import base64
import datetime
import json
import os
import random
import string
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict

import click
import kubernetes as k8s
import yaml
from click import ClickException
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, asymmetric, hashes

from kxicli import common
from kxicli import phrases
from kxicli import log
from kxicli import options
from kxicli.commands import assembly
from kxicli.commands.common import arg_force, arg_filepath, arg_version, arg_operator_version, \
    arg_release, arg_namespace, arg_assembly_backup_filepath, arg_output_file, arg_hostname, \
    arg_chart_repo_name, arg_chart_repo_name_forced, arg_chart_repo_url, arg_chart_repo_username, arg_chart_repo_password, \
    arg_license_secret, arg_license_as_env_var, arg_license_filepath, arg_client_cert_secret, \
    arg_image_repo, arg_image_repo_user, arg_image_pull_secret, arg_gui_client_secret, arg_operator_client_secret, \
    arg_keycloak_secret, arg_keycloak_postgresql_secret, arg_keycloak_auth_url, \
    arg_ingress_cert_secret, arg_ingress_cert, arg_ingress_key, \
    arg_install_config_secret, arg_install_config_secret_default
from kxicli.common import get_default_val as default_val
from kxicli.common import get_help_text as help_text
from kxicli.resources import secret, helm

DOCKER_CONFIG_FILE_PATH = str(Path.home() / '.docker' / 'config.json')
operator_namespace = 'kxi-operator'

SECRET_TYPE_TLS = 'kubernetes.io/tls'
SECRET_TYPE_DOCKERCONFIG_JSON = 'kubernetes.io/dockerconfigjson'
SECRET_TYPE_OPAQUE = 'Opaque'

TLS_CRT = 'tls.crt'
TLS_KEY = 'tls.key'

VALUES_YAML = 'values.yaml'

# Basic validation for secrets
KEYCLOAK_KEYS =  ('admin-password', 'management-password')
POSTGRESQL_KEYS =  ('postgresql-postgres-password', 'postgresql-password')
LICENSE_KEYS = ('license',)
IMAGE_PULL_KEYS =  ('.dockerconfigjson',)
INGRESS_CERT_KEYS = (TLS_CRT, TLS_KEY)
CLIENT_CERT_KEYS = (TLS_CRT, TLS_KEY)
INSTALL_CONFIG_KEYS = (VALUES_YAML,)

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

@click.group()
def install():
    """Insights installation commands"""


@install.command()
@arg_namespace()
@arg_chart_repo_name()
@arg_chart_repo_url()
@arg_chart_repo_username()
@arg_license_secret()
@arg_license_as_env_var()
@arg_license_filepath()
@arg_client_cert_secret()
@arg_image_repo()
@arg_image_repo_user()
@arg_image_pull_secret()
@arg_gui_client_secret()
@arg_operator_client_secret()
@arg_keycloak_secret()
@arg_keycloak_postgresql_secret()
@arg_keycloak_auth_url()
@arg_hostname()
@arg_ingress_cert_secret()
@arg_ingress_cert()
@arg_ingress_key()
@arg_output_file()
@arg_install_config_secret_default()
def setup(namespace, chart_repo_name, chart_repo_url, chart_repo_username, 
          license_secret, license_as_env_var, license_filepath,
          client_cert_secret, image_repo, image_repo_user, image_pull_secret, gui_client_secret, operator_client_secret,
          keycloak_secret, keycloak_postgresql_secret, keycloak_auth_url, hostname, 
          ingress_cert_secret, ingress_cert, ingress_key,
          output_file, install_config_secret):
    """Perform necessary setup steps to install Insights"""
    
    click.secho(phrases.header_setup, bold=True)

    active_context, namespace = common.get_namespace(namespace)
    create_namespace(namespace)
    click.echo(phrases.ns_and_cluster.format(namespace=namespace, \
        cluster=active_context["context"]["cluster"]))


    install_config_secret = secret.Secret(namespace, install_config_secret, SECRET_TYPE_OPAQUE, INSTALL_CONFIG_KEYS)
    values_secret = get_install_config_secret(install_config_secret)
    # Setup secret by looking for them in the following hierarchy
    #   - cmd line arg
    #      - values file (currently None in this command)
    #        - values secret if it exists
    #          - value configured in cli-config file
    #            - value in DEFAULT_VALUES
    license_secret = lookup_secret(namespace, license_secret, values_secret, None, license_key)
    client_cert_secret = lookup_secret(namespace, client_cert_secret, values_secret, None, 'client.cert.secret')
    image_pull_secret = lookup_secret(namespace, image_pull_secret, values_secret, None, image_pull_key)
    keycloak_secret = lookup_secret(namespace, keycloak_secret, values_secret, None, 'keycloak.secret')
    keycloak_postgresql_secret = lookup_secret(namespace, keycloak_postgresql_secret, values_secret, None, 'keycloak.postgresqlSecret')
    ingress_cert_secret_object = lookup_secret(namespace, ingress_cert_secret, values_secret, None, 'ingress.cert.secret')

    click.secho(phrases.header_ingress, bold=True)
    hostname = sanitize_ingress_host(options.hostname.prompt(hostname))
    ingress_self_managed, ingress_cert_secret_object = prompt_for_ingress_cert(ingress_cert_secret_object, ingress_cert_secret, ingress_cert, ingress_key)

    click.secho(phrases.header_chart, bold=True)
    chart_repo_name = options.chart_repo_name.prompt(chart_repo_name)
    if any (chart_repo_name == item['name'] for item in helm_repo_list()):
       click.echo(f'Using existing helm repo {chart_repo_name}')
    else:
        chart_repo_url = options.chart_repo_url.prompt(chart_repo_url)
        username = options.chart_repo_username.prompt(chart_repo_username)
        password = options.chart_repo_password.prompt()
        helm_add_repo(chart_repo_name, chart_repo_url, username, password)

    click.secho(phrases.header_license, bold=True)
    license_secret, license_on_demand = prompt_for_license(license_secret, license_as_env_var)

    click.secho(phrases.header_image, bold=True)
    image_repo, image_pull_secret = prompt_for_image_details(image_pull_secret, image_repo, image_repo_user)

    click.secho(phrases.header_client_cert, bold=True)
    client_cert_secret = ensure_secret(client_cert_secret, populate_cert)

    click.secho(phrases.header_keycloak, bold=True)
    if deploy_keycloak():
        keycloak_secret = ensure_secret(keycloak_secret, populate_keycloak_secret)
        keycloak_postgresql_secret = ensure_secret(keycloak_postgresql_secret, populate_postgresql_secret)

    if not gui_client_secret:
        gui_client_secret = prompt_for_client_secret('gui')
        common.config.append_config(profile=common.config.config.default_section, name='guiClientSecret',
                                    value=gui_client_secret)

    if not operator_client_secret:
        operator_client_secret = prompt_for_client_secret('operator')
        common.config.append_config(profile=common.config.config.default_section, name='operatorClientSecret',
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

    if ingress_self_managed:
        install_file['global']['ingress']['certmanager'] = False
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

    create_install_config(install_config_secret, install_file)

    click.secho(phrases.footer_setup, bold=True)
    click.echo(phrases.values_file_saved.format(output_file=output_file))

    return output_file, chart_repo_name


@install.command()
@arg_namespace()
@arg_filepath()
@arg_release()
@arg_chart_repo_name_forced()
@arg_version()
@arg_operator_version()
@arg_image_pull_secret()
@arg_license_secret()
@arg_install_config_secret()
@arg_force()
@click.pass_context
def run(ctx, namespace, filepath, release, chart_repo_name, version, operator_version, image_pull_secret,
        license_secret, install_config_secret, force):
    """Install KX Insights with a values file"""

    # Run setup prompts if necessary
    if filepath is None and install_config_secret is None:
        click.echo(phrases.header_run)
        filepath, chart_repo_name = ctx.invoke(setup)

    _, namespace = common.get_namespace(namespace)

    install_config_secret = secret.Secret(namespace, install_config_secret, SECRET_TYPE_OPAQUE, INSTALL_CONFIG_KEYS)

    values_secret = get_install_values(install_config_secret)
    image_pull_secret, license_secret = get_image_and_license_secret_from_values(values_secret, filepath,
                                                                                 image_pull_secret, license_secret)

    validate_values(namespace, values_secret, filepath)

    insights_installed_charts = get_installed_charts(release, namespace)
    if len(insights_installed_charts) > 0:
        if click.confirm(f'KX Insights is already installed with version {insights_installed_charts[0]["chart"]}. Would you like to upgrade to version {version}?'):
            return perform_upgrade(namespace, release, chart_repo_name, default_val('assembly.backup.file'), version,
                                   operator_version, image_pull_secret, license_secret, install_config_secret,
                                   filepath, force)
        else:
            sys.exit(0)

    install_operator, is_op_upgrade, operator_version, crd_data = check_for_operator_install(release,
        chart_repo_name, version, operator_version, force)

    install_operator_and_release(release, namespace, version, operator_version, filepath, values_secret,
                                 image_pull_secret, license_secret, chart_repo_name,
                                 install_operator, is_op_upgrade, crd_data)

@install.command()
@arg_namespace()
@arg_release()
@arg_chart_repo_name_forced()
@arg_assembly_backup_filepath()
@arg_version()
@arg_operator_version()
@arg_image_pull_secret()
@arg_license_secret()
@arg_install_config_secret()
@arg_filepath()
@arg_force()
def upgrade(namespace, release, chart_repo_name, assembly_backup_filepath, version, operator_version, image_pull_secret,
            license_secret, install_config_secret, filepath, force):
    perform_upgrade(namespace, release, chart_repo_name, assembly_backup_filepath, version, operator_version, image_pull_secret,
                    license_secret, install_config_secret, filepath, force)

def perform_upgrade(namespace, release, chart_repo_name, assembly_backup_filepath, version, operator_version, image_pull_secret,
                    license_secret, install_config_secret, filepath, force):
    """Upgrade KX Insights"""
    _, namespace = common.get_namespace(namespace)

    upgraded = False
    click.secho(phrases.header_upgrade, bold=True)

    # Read install values
    if filepath is None and install_config_secret is None:
        log.error('At least one of --install-config-secret and --filepath options must be provided')
        sys.exit(1)

    if not isinstance(install_config_secret, secret.Secret):
        install_config_secret = secret.Secret(namespace, install_config_secret, SECRET_TYPE_OPAQUE, INSTALL_CONFIG_KEYS)

    values_secret = get_install_values(install_config_secret)
    image_pull_secret, license_secret = get_image_and_license_secret_from_values(values_secret, filepath,
                                                                                 image_pull_secret, license_secret)

    validate_values(namespace, values_secret, filepath)

    install_operator, is_op_upgrade, operator_version, crd_data = check_for_operator_install(release,
        chart_repo_name, version, operator_version, force)

    if not insights_installed(release, namespace):
        click.echo(phrases.upgrade_skip_to_install)
        install_operator_and_release(release, namespace, version, operator_version, filepath, values_secret,
                                 image_pull_secret, license_secret, chart_repo_name,
                                 install_operator, is_op_upgrade, crd_data)
        click.secho(str.format(phrases.upgrade_complete, version=version), bold=True)
        sys.exit(0)

    click.secho(phrases.upgrade_asm_backup, bold=True)
    assembly_backup_filepath = assembly._backup_assemblies(namespace, assembly_backup_filepath, force)

    click.secho(phrases.upgrade_asm_teardown, bold=True)
    click.secho(phrases.upgrade_asm_persist)

    try:
        deleted = assembly._delete_running_assemblies(namespace=namespace, wait=True, force=force)

        if all(deleted):
            click.secho(phrases.upgrade_insights_and_op, bold=True)
            upgraded =  install_operator_and_release(release, namespace, version, operator_version, filepath, values_secret,
                                                    image_pull_secret, license_secret, chart_repo_name,
                                                    install_operator, is_op_upgrade, crd_data)
    except BaseException as e:
        log.error(phrases.upgrade_error)
        assembly._create_assemblies_from_file(namespace=namespace, filepath=assembly_backup_filepath)
        raise e

    click.secho(phrases.upgrade_asm_reapply, bold=True)
    assembly._create_assemblies_from_file(namespace=namespace, filepath=assembly_backup_filepath)

    if upgraded:
        click.secho(str.format(phrases.upgrade_complete, version=version), bold=True)


@install.command()
@arg_release()
@arg_namespace()
@arg_force()
@click.option('--uninstall-operator', is_flag=True, help='Remove KXI Operator installation')
def delete(release, namespace, force, uninstall_operator):
    """Uninstall KX Insights"""
    _, namespace = common.get_namespace(namespace)
    delete_release_operator_and_crds(release=release, namespace=namespace, force=force, uninstall_operator=uninstall_operator)


@install.command()
@arg_chart_repo_name_forced()
def list_versions(chart_repo_name):
    """
    List available versions of KX Insights
    """
    helm_list_versions(chart_repo_name)


@install.command()
@arg_namespace()
@arg_install_config_secret_default()
def get_values(namespace, install_config_secret):
    """
    Display the kxi-install-config secret used for storing installation values
    """
    install_config_secret = secret.Secret(namespace, install_config_secret, SECRET_TYPE_OPAQUE, INSTALL_CONFIG_KEYS)

    data = get_install_config_secret(install_config_secret)
    if data is None:
        click.echo(f'Cannot find values secret {install_config_secret.name}\n')
    else:
        click.echo(data)


def get_install_config_secret(install_config_secret: secret.Secret):
    """
    Return the kxi-install-config secret used for storing installation values
    """
    values_secret = install_config_secret.read()
    if values_secret:
        values_secret = base64.b64decode(values_secret.data[VALUES_YAML]).decode('ascii')
    else:
        log.debug(f'Cannot find values secret {install_config_secret.name}')

    return values_secret


def get_operator_version(chart_repo_name, insights_version, operator_version):
    """Determine operator version to use. Retrieve the most recent operator minor version matching the insights version"""
    if operator_version is None:
        insights_version_parsed = insights_version.split(".")
        insights_version_minor = insights_version_parsed[0] + "." + insights_version_parsed[1]
        ops_from_helm = subprocess.run(
            ['helm', 'search', 'repo', f'{chart_repo_name}/kxi-operator', '--version', f'{insights_version_minor}',
             '--output', 'json'], check=True, capture_output=True, text=True)
        ops_from_helm = json.loads(ops_from_helm.stdout)
        if len(ops_from_helm):
            operator_version = ops_from_helm[0]['version']
        else:
            log.error(f'Cannot find operator version matching insights minor version {insights_version_minor}')
            sys.exit(1)
    return operator_version


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


def prompt_for_license(secret: secret.Secret, license_as_env_var):
    """Prompt for an existing license or create on if it doesn't exist"""
    license_on_demand = False

    exists, is_valid, _ = secret.validate()
    if not exists:
        secret, license_on_demand = populate_license_secret(secret, as_env=license_as_env_var)
        secret.create()
    elif not is_valid:
        if click.confirm(phrases.secret_exist_invalid.format(name=secret.name)):
            click.echo(phrases.secret_overwriting.format(name=secret.name))
            secret, license_on_demand = populate_license_secret(secret, as_env=license_as_env_var)
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

    if existing_config:
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
    admin_password = common.enter_password(phrases.keycloak_admin)
    management_password = common.enter_password(phrases.keycloak_manage)

    secret.data = {
            'admin-password': base64.b64encode(admin_password.encode()).decode('ascii'),
            'management-password': base64.b64encode(management_password.encode()).decode('ascii')
        }

    return secret


def populate_postgresql_secret(secret: secret.Secret, **kwargs):
    postgresql_postgres_password = common.enter_password(phrases.postgresql_postgres)
    postgresql_password = common.enter_password(phrases.postgresql_user)

    secret.data = {
            'postgresql-postgres-password': base64.b64encode(postgresql_postgres_password.encode()).decode('ascii'),
            'postgres-password': base64.b64encode(postgresql_postgres_password.encode()).decode('ascii'),
            'postgresql-password': base64.b64encode(postgresql_password.encode()).decode('ascii'),
            'password': base64.b64encode(postgresql_password.encode()).decode('ascii')
        }

    return secret


def prompt_for_ingress_cert(secret: secret.Secret, name, ingress_cert, ingress_key):
    if name:
        ingress_self_managed = True
    elif click.confirm(phrases.ingress_cert):
        ingress_self_managed = True
        secret = ensure_secret(secret, populate_ingress_cert,
            {
                'ingress_cert':ingress_cert, 
                'ingress_key': ingress_key
            }
        )
    else:
        click.echo(phrases.ingress_lets_encrypt)
        ingress_self_managed = False

    return ingress_self_managed, secret


def populate_ingress_cert(secret: secret.Secret, **kwargs):
    path_to_cert = options.ingress_cert.prompt(kwargs.get('ingress_cert'))
    with open(path_to_cert, 'r') as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data.encode(), backend=default_backend())

    path_to_key = options.ingress_key.prompt(kwargs.get('ingress_key'))
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
        '.dockerconfigjson': base64.b64encode(docker_config).decode('ascii')
    }
    return secret


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

def populate_install_secret(secret: secret.Secret, data: Dict):
    secret.data = {VALUES_YAML: base64.b64encode(yaml.dump(data['values']).encode()).decode('ascii')}
    return secret


def get_install_values(install_config_secret: secret.Secret):
    values_secret = None
    if install_config_secret.name:
        values_secret = get_install_config_secret(install_config_secret)
        if not values_secret:
            click.echo(f'Cannot find values secret {install_config_secret.name}. Exiting Install\n')
            sys.exit(1)

    return values_secret


def get_image_and_license_secret_from_values(values_secret, values_file, image_pull_secret, license_secret):
    """Read image_pull_secret and license_secret from argument, values file, values secret, default"""
    values_secret_dict, values_file_dict = load_values_stores(values_secret, values_file)
    if image_pull_secret is None:
        image_pull_secret = get_from_values_store(['global', 'imagePullSecrets', 0, 'name'], values_secret_dict,
                                                 values_file_dict, default_val(image_pull_key))

    if license_secret is None:
        license_secret = get_from_values_store(['global', 'license', 'secretName'], values_secret_dict, values_file_dict,
                                              default_val(license_key))

    return image_pull_secret, license_secret

def load_values_stores(values_secret, values_file):
    values_secret_dict = {}
    if values_secret:
        values_secret_dict = yaml.safe_load(values_secret)

    values_file_dict = {}
    if values_file:
        if not os.path.exists(values_file):
            log.error(f'File not found: {values_file}. Exiting')
            sys.exit(1)
        else:
            with open(values_file) as f:
                try:
                    values_file_dict = yaml.safe_load(f)
                except yaml.YAMLError as e:
                    log.error(f'Invalid values file {values_file}')
                    click.echo(e)
                    sys.exit(1)

    return values_secret_dict, values_file_dict

def get_from_values_store(key, values_secret_dict, values_file_dict, default):
    try:
        val = values_file_dict
        for k in key:
            val = val[k]
        log.debug(f'Using key {key} in values file')
    except KeyError:
        try:
            val = values_secret_dict
            for k in key:
                val = val[k]
            log.debug(f'Using key {key} in values secret')
        except KeyError:
            val = default
            log.debug(f'Cannot find key {key} in values file or secret. Using default {default}')
        except BaseException as e:
            log.error(f'Invalid values secret')
            log.error(e)
            sys.exit(1)
    except BaseException as e:
        log.error(f'Invalid values file')
        log.error(e)
        sys.exit(1)

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


def check_for_operator_install(release, chart_repo_name, insights_ver, op_ver, force):
    """
    Determine if the operator needs to be install or upgraded
    Fetch the CRD data if it's an upgrade
    This all happens prior to install / upgrade so we can exit cleanly in the event of an exception
    """
    operator_installed_charts = get_installed_charts(release, operator_namespace)
    is_upgrade = len(operator_installed_charts) > 0

    if is_upgrade:
        click.echo(f'\nkxi-operator already installed with version {operator_installed_charts[0]["chart"]}')
    else:
        click.echo(f'\nkxi-operator not found')

    operator_version_to_install = get_operator_version(chart_repo_name, insights_ver, op_ver)
    install_operator = force or click.confirm(f'Do you want to install kxi-operator version {operator_version_to_install}?', default=True)

    crd_data = []
    if install_operator and is_upgrade:
        cache = helm.get_repository_cache()
        helm.fetch(chart_repo_name, 'kxi-operator', cache, operator_version_to_install)
        crd_data = read_cached_crd_files(operator_version_to_install)

    return install_operator, is_upgrade, operator_version_to_install, crd_data


def install_operator_and_release(
    release,
    namespace,
    version,
    operator_version,
    values_file,
    values_secret,
    image_pull_secret,
    license_secret,
    chart_repo_name,
    install_operator = True,
    is_operator_upgrade = False,
    crd_data = []
):
    """Install operator and insights"""

    subprocess.run(['helm', 'repo', 'update'], check=True)

    if install_operator:
        create_namespace(operator_namespace)

        copy_secret(image_pull_secret, namespace, operator_namespace)
        copy_secret(license_secret, namespace, operator_namespace)

        helm_install(release, chart=f'{chart_repo_name}/kxi-operator', values_file=values_file, values_secret=values_secret,
            version=operator_version, namespace=operator_namespace)

        if is_operator_upgrade:
            replace_chart_crds(crd_data)

    insights_installed_charts = get_installed_charts(release, namespace)
    if len(insights_installed_charts) > 0:
        click.echo(f'\nKX Insights already installed with version {insights_installed_charts[0]["chart"]}')

    helm_install(release, chart=f'{chart_repo_name}/insights', values_file=values_file, values_secret=values_secret,
            version=version, namespace=namespace)

    return True


def delete_release_operator_and_crds(release, namespace, force, uninstall_operator):
    """Delete insights, operator and CRDs"""
    if not insights_installed(release, namespace):
        click.echo('\nKX Insights installation not found')
    else:
        if force or click.confirm('\nKX Insights is deployed. Do you want to uninstall?'):
            assembly._delete_running_assemblies(namespace, True, True)
            helm_uninstall(release=release, namespace=namespace)
        else:
            return

    if force or operator_installed(release) and uninstall_operator:
        helm_uninstall(release=release, namespace=operator_namespace)

        crds = common.get_existing_crds(CRD_NAMES)
        if len(crds) > 0:
            for i in crds:
                common.delete_crd(i)


def helm_add_repo(chart_repo_name, url, username, password):
    """Call 'helm repo add' using subprocess.run"""
    log.debug(
        f'Attempting to call: helm repo add --username {username} --password {len(password)*"*"} {chart_repo_name} {url}')
    try:
        return subprocess.run(['helm', 'repo', 'add', '--username', username, '--password', password, chart_repo_name, url],
                       check=True)
    except subprocess.CalledProcessError:
        # Pass here so that the password isn't printed in the log
        pass


def helm_repo_list():
    """Call 'helm repo list' using subprocess.run"""
    log.debug('Attempting to call: helm repo list')
    try:
        res = subprocess.run(
            ['helm', 'repo', 'list', '--output', 'json'], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        click.echo(e)
    return json.loads(res.stdout)


def helm_list_versions(chart_repo_name):
    """Call 'helm search repo' using subprocess.run"""
    log.debug('Attempting to call: helm search repo')
    try:
        chart = f'{chart_repo_name}/insights'
        click.echo(f'Listing available KX Insights versions in repo {chart_repo_name}')

        return subprocess.run(['helm', 'search', 'repo', chart], check=True)
    except subprocess.CalledProcessError as e:
        raise ClickException(str(e))


def helm_install(release, chart, values_file, values_secret, version=None, namespace=None):
    """Call 'helm install' using subprocess.run"""

    base_command = ['helm', 'upgrade', '--install']

    if values_secret:
        base_command = base_command + ['-f', '-']
        input_arg = values_secret
        text_arg = True
    else:
        input_arg=None
        text_arg=None

    if values_file:
        base_command = base_command + ['-f', values_file]

    base_command = base_command + [release, chart]

    version_msg = ''
    if version:
        version_msg = ' version ' + version
        base_command = base_command + ['--version', version]

    if values_file:
        if values_secret:
            click.echo(f'Installing chart {chart}{version_msg} with values from secret and values file from {values_file}')
        else:
            click.echo(f'Installing chart {chart}{version_msg} with values file from {values_file}')
    else:
        if values_secret:
            click.echo(f'Installing chart {chart}{version_msg} with values from secret')
        else:
            click.echo(f'Must provide one of values file or secret. Exiting install')
            sys.exit(1)

    if namespace:
        base_command = base_command + ['--namespace', namespace]
        create_namespace(namespace)

    try:
        log.debug(f'Install command {base_command}')
        return subprocess.run(base_command, check=True, input=input_arg, text=text_arg)
    except subprocess.CalledProcessError as e:
        raise ClickException(str(e))


def helm_uninstall(release, namespace=None):
    """Call 'helm uninstall' using subprocess.run"""

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


def create_namespace(name):
    common.load_kube_config()
    api = k8s.client.CoreV1Api()
    ns = k8s.client.V1Namespace()
    ns.metadata = k8s.client.V1ObjectMeta(name=name)
    try:
        api.create_namespace(ns)
    except k8s.client.rest.ApiException as exception:
        # 409 is a conflict, this occurs if the namespace already exists
        if not exception.status == 409:
            log.error(f'Exception when trying to create namespace {exception}')
            sys.exit(1)


def copy_secret(name, from_ns, to_ns):
    common.load_kube_config()
    api = k8s.client.CoreV1Api()
    try:
        secret = api.read_namespaced_secret(namespace=from_ns, name=name)
    except k8s.client.rest.ApiException as exception:
        log.error(f'Exception when trying to get secret {exception}')
        sys.exit(1)

    secret.metadata = k8s.client.V1ObjectMeta(namespace=to_ns, name=name)

    try:
        secret = api.create_namespaced_secret(namespace=to_ns, body=secret)
    except k8s.client.rest.ApiException as exception:
        if not exception.status == 409:
            log.error(f'Exception when trying to create secret {exception}')
            sys.exit(1)


def prompt_for_client_secret(client_name):
    if click.confirm(phrases.service_account_secret.format(name=client_name)):
        client_secret = common.enter_password(phrases.secret_entry)
    else:
        click.echo(phrases.service_account_random.format(name=client_name))
        client_secret = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(10))

    return client_secret


def insights_installed(release, namespace):
    """Check if a helm release of insights exists"""
    return len(get_installed_charts(release, namespace)) > 0


def operator_installed(release, namespace: str = operator_namespace):
    """Check if a helm release of the operator exists"""
    return len(get_installed_charts(release, namespace)) > 0

def get_installed_charts(release, namespace):
    """Retrieve running helm charts"""
    base_command = ['helm', 'list', '--filter', release, '-o', 'json','--namespace', namespace]
    try:
        log.debug(f'List command {base_command}')
        l = subprocess.check_output(base_command)
        return json.loads(l)
    except subprocess.CalledProcessError as e:
        click.echo(e)


# Check if Keycloak is being deployed with Insights
def deploy_keycloak():
    return '--keycloak-auth-url' not in sys.argv


# Structure of the config:
#   name: (key in values file, secret type, required keys, mandatory)
def get_secret_config():
    return {
        license_key: (['global', 'license', 'secretName'], SECRET_TYPE_OPAQUE, LICENSE_KEYS, True),
        'client.cert.secret': (['global', 'caIssuer', 'secretName'],  SECRET_TYPE_TLS, CLIENT_CERT_KEYS, True),
        image_pull_key: (['global', 'imagePullSecret', 0, 'name'], SECRET_TYPE_DOCKERCONFIG_JSON, IMAGE_PULL_KEYS, True),
        'keycloak.secret': (['keycloak', 'auth', 'existingSecret'], SECRET_TYPE_OPAQUE, KEYCLOAK_KEYS, deploy_keycloak()),
        'keycloak.postgresqlSecret': (['keycloak', 'postgresql', 'existingSecret'], SECRET_TYPE_OPAQUE, POSTGRESQL_KEYS, deploy_keycloak()),
        'ingress.cert.secret': (['global', 'ingress', 'tlsSecret'], SECRET_TYPE_TLS, INGRESS_CERT_KEYS, False)
    }


def validate_values(namespace, values_secret, values_file):
    click.echo(phrases.values_validating)
    values_secret_dict, values_file_dict = load_values_stores(values_secret, values_file)

    exit_execution = False
    for k, v in get_secret_config().items():
        # if the secret is mandatory, validate it
        if v[3]:
            default = default_val(k)
            name = get_from_values_store(v[0], values_secret_dict, values_file_dict, default)
            exists, is_valid, _ = secret.Secret(namespace, name, v[1], v[2]).validate()
            if not exists:
                log.error(phrases.secret_validation_not_exist.format(name=name))
                exit_execution = True
            elif not is_valid:
                log.error(phrases.secret_validation_invalid.format(name=name, type=v[1], keys=v[2]))
                exit_execution = True
    if exit_execution:
        click.echo(phrases.values_validation_fail)
        sys.exit(1)


def lookup_secret(namespace, arg, values_secret, values_file, default_key):
    values_secret_dict, values_file_dict = load_values_stores(values_secret, values_file)

    # lookup the secret configuration in the config
    v = get_secret_config()[default_key]

    # if the name isn't passed as an argument, look it up in the values stores
    if arg is None:
        log.debug(f'No command line argument passed for {default_key}, looking up in values stores')
        arg = get_from_values_store(v[0], values_secret_dict, values_file_dict, default_val(default_key))

    s = secret.Secret(namespace, arg, v[1], v[2])
    return s

def create_install_config(install_config_secret: secret.Secret, data):
    install_config_secret = populate_install_secret(install_config_secret, data={'values': data})
    if install_config_secret.exists():
        if click.confirm(phrases.secret_exist.format(name=install_config_secret.name)):
            click.echo(phrases.secret_overwriting.format(name=install_config_secret.name))
            install_config_secret.patch()
    else:
        install_config_secret.create()

    return install_config_secret

def read_cached_crd_files(
    version: str,
    chart_name: str = 'kxi-operator',
    crds: list = CRD_FILES
):
    crd_data = []

    cache = helm.get_repository_cache()
    tar_path = Path(cache) / f'{chart_name}-{version}.tgz'

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
