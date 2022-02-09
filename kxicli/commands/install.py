import sys
import os
import string
import random
import subprocess
import datetime
import base64
import json
import click
import kubernetes as k8s
import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, asymmetric, hashes
from kxicli import log
from kxicli import common
from kxicli.common import get_default_val as default_val
from kxicli.common import get_help_text as help_text

docker_config_file_path = os.environ.get('HOME') + '/.docker/config.json'
install_namespace_default = 'kxi'
operator_namespace = 'kxi-operator'

@click.group()
def install():
    """Insights installation commands"""

@install.command()
@click.option('--namespace', default=lambda: default_val('namespace'), help=help_text('namespace'))
@click.option('--chart-repo-name', default=lambda: default_val('chart.repo.name'), help=help_text('chart.repo.name'))
@click.option('--license-secret', default=lambda: default_val('license.secret'), help=help_text('license.secret'))
@click.option('--client-cert-secret', default=lambda: default_val('client.cert.secret'), help=help_text('client.cert.secret'))
@click.option('--image-repo', default=lambda: default_val('image.repository'), help=help_text('image.repository'))
@click.option('--image-pull-secret', default=lambda: default_val('image.pullSecret'), help=help_text('image.pullSecret'))
@click.option('--gui-client-secret', default=lambda: default_val('guiClientSecret'), help=help_text('guiClientSecret'))
@click.option('--operator-client-secret', default=lambda: default_val('operatorClientSecret'), help=help_text('operatorClientSecret'))
@click.option('--keycloak-secret', default=lambda: default_val('keycloak.secret'), help=help_text('keycloak.secret'))
@click.option('--keycloak-postgresql-secret', default=lambda: default_val('keycloak.postgresqlSecret'), help=help_text('keycloak.postgresqlSecret'))
@click.option('--ingress-host', help=help_text('ingress.host'))
@click.option('--ingress-cert-secret', default=lambda: default_val('ingress.cert.secret'), help=help_text('ingress.cert.secret'))
@click.option('--output-file', default=lambda: default_val('install.outputFile'), help=help_text('install.outputFile'))
def setup(namespace, chart_repo_name, license_secret, client_cert_secret, image_repo, image_pull_secret, gui_client_secret, operator_client_secret,
                keycloak_secret, keycloak_postgresql_secret, ingress_host, ingress_cert_secret, output_file):
    """Perform necessary setup steps to install Insights"""

    click.secho('KX Insights Install Setup', bold=True)

    _, active_context = k8s.config.list_kube_config_contexts()
    if '--namespace' not in sys.argv:
        if 'namespace' in active_context['context']:
            namespace = active_context['context']['namespace']
        else:
            namespace = click.prompt('\nPlease enter a namespace to install in', default=install_namespace_default)

    create_namespace(namespace)
    click.echo(f'\nRunning in namespace {namespace} on the cluster {active_context["context"]["cluster"]}')

    if '--ingress-host' not in sys.argv:
        ingress_host = sanitize_ingress_host(click.prompt('\nPlease enter the hostname for the installation'))

    if '--chart-repo-name' not in sys.argv:
        click.secho('\nChart details', bold=True)
        chart_repo_name = click.prompt('Please enter a name for the chart repository to set locally', default=default_val('chart.repo.name'))
        chart_repo_url = click.prompt('Please enter the chart repository URL to pull charts from', default=default_val('chart.repo.url'))
        username = click.prompt('Please enter the username for the chart repository')
        password = click.prompt('Please enter the password for the chart repository (input hidden)', hide_input=True)
        helm_add_repo(chart_repo_name, chart_repo_url, username, password)

    if '--license-secret' not in sys.argv:
        click.secho('\nLicense details', bold=True)
        license_secret = prompt_for_license(namespace, license_secret)

    if not('--image-repo' in sys.argv and '--image-pull-secret' in sys.argv):
        click.secho('\nImage repository', bold=True)
        image_repo, image_pull_secret = prompt_for_image_details(namespace, image_repo, image_pull_secret)

    if '--client-cert-secret' not in sys.argv:
        click.secho('\nClient certificate issuer', bold=True)
        client_cert_secret = prompt_for_client_cert(namespace, client_cert_secret)

    if not('--keycloak-secret' in sys.argv and '--keycloak-postgresql-secret' in sys.argv):
        click.secho('\nKeycloak', bold=True)
        keycloak_secret, keycloak_postgresql_secret = prompt_for_keycloak(namespace, keycloak_secret, keycloak_postgresql_secret)

    if '--gui-client-secret' not in sys.argv:
        gui_client_secret = prompt_for_client_secret('gui')

    if '--operator-client-secret' not in sys.argv:
        operator_client_secret = prompt_for_client_secret('operator')

    if 'ingress-cert-secret' not in sys.argv:
        click.secho('\nIngress', bold=True)
        ingress_self_managed, ingress_cert_secret = prompt_for_ingress_cert(namespace, ingress_cert_secret)

    # These keys must all exist, conditionally defined
    # keys like the self-managed ingress cert are handled afterwards
    install_file = {
        'global': {
            'ingress': {
                'host': ingress_host
            },
            'license': {
                'secretName': license_secret
            },
            'caIssuer': {
               'name': client_cert_secret,
               'secretName': client_cert_secret
            },
            'image': {
                'repository': image_repo
            },
            'imagePullSecrets': [
                {
                    'name': image_pull_secret
                }
            ],
            'keycloak': {
                'guiClientSecret': gui_client_secret,
                'operatorClientSecret': operator_client_secret
            }
        },
        'keycloak': {
            'auth': {
                'existingSecret': keycloak_secret
            },
            'postgresql': {
                'existingSecret': keycloak_postgresql_secret
            }
        }
    }

    if ingress_self_managed:
        install_file['global']['ingress']['certmanager']: False
        install_file['global']['ingress']['tlsSecret']: ingress_cert_secret

    with open(output_file, 'w') as f:
        yaml.dump(install_file, f)

    click.secho('\nKX Insights installation setup complete', bold=True)
    click.echo(f'\nHelm values file for installation saved in {output_file}\n')

    return output_file, chart_repo_name

@install.command()
@click.option('--filepath', help='Values file to install with')
@click.option('--release', default=lambda: default_val('release.name'), help=help_text('release.name'))
@click.option('--repo', default=lambda: default_val('chart.repo.name'), help=help_text('chart.repo.name'))
@click.option('--version', default=None, help='Version to install')
@click.option('--operator-version', default=None, help='Version of the operator to install')
@click.option('--image-pull-secret', default=lambda: default_val('image.pullSecret'), help=help_text('image.pullSecret'))
@click.option('--license-secret', default=lambda: default_val('license.secret'), help=help_text('license.secret'))
@click.pass_context
def run(ctx, filepath, release, repo, version, operator_version, image_pull_secret, license_secret):
    """Install KX Insights with a values file"""

    # Run setup prompts if necessary
    if '--filepath' not in sys.argv:
        if click.confirm('\nNo values file provided, do you want to generate one now'):
            click.echo('Invoking "kxi install setup"\n')
            filepath, repo = ctx.invoke(setup)
        else:
            filepath = click.prompt('Please enter the path to the values file for the install')

    install_operator = True
    if common.crd_exists('assemblies.insights.kx.com'):
        install_operator = False
        if click.confirm('\nThe assemblies.insights.kx.com CRD exists, do you want to install the operator'):
            install_operator = True

    if install_operator:
        create_namespace(operator_namespace)

        _, active_context = k8s.config.list_kube_config_contexts()
        from_ns = active_context['context']['namespace']
        copy_secret(image_pull_secret, from_ns, operator_namespace)
        copy_secret(license_secret, from_ns, operator_namespace)

        chart=repo+'/kxi-operator'
        helm_install(release, chart=chart, values_file=filepath, version=operator_version, namespace=operator_namespace)

    chart=repo+'/insights'
    helm_install(release, chart=chart, values_file=filepath, version=version)

def sanitize_ingress_host(raw_string):
    """Santize a host name to allow it to be used"""
    return raw_string.replace('http://', '').replace('https://', '')

def prompt_for_license(namespace, license_secret):
    """Prompt for an existing license or create on if it doesn't exist"""
    if click.confirm('Do you have an existing license secret'):
        license_secret = prompt_for_existing_secret()
    else:
        path_to_lic = click.prompt('Please enter the path to your kdb license')
        create_license_secret(namespace, license_secret, path_to_lic)

    return license_secret

def prompt_for_client_cert(namespace, client_cert_secret):
    """Prompt for an existing client cert secret or create one if it doesn't exist"""
    if click.confirm('Do you have an existing client certificate issuer'):
        client_cert_secret = prompt_for_existing_secret()
    else:
        key = gen_private_key()
        cert = gen_cert(key)
        create_tls_secret(namespace, client_cert_secret, cert, key)

    return client_cert_secret

def prompt_for_image_details(namespace, image_repo, image_pull_secret):
    """Prompt for an existing image pull secret or create on if it doesn't exist"""
    image_repo = click.prompt('Please enter the image repository to pull images from', default=image_repo)

    if click.confirm(f'Do you have an existing image pull secret for {image_repo}'):
        image_pull_secret = prompt_for_existing_secret()
        return image_repo, image_pull_secret

    existing_config = check_existing_docker_config(image_repo, docker_config_file_path)

    if existing_config:
        # parse the user from the existing config which is a base64 encoded string of "username:password"
        user = base64.b64decode(existing_config['auth']).decode('ascii').split(':')[0]
        if click.confirm(f'Credentials {user}@{image_repo} exist in {docker_config_file_path}, do you want to use these'):
            docker_config = {
                'auths': {
                    image_repo: existing_config
                }
            }
            create_docker_config_secret(namespace, image_pull_secret, docker_config)
            return image_repo, image_pull_secret

    user = click.prompt(f'Please enter the username for {image_repo}')
    password = click.prompt(f'Please enter the password for {user} (input hidden)', hide_input=True)
    docker_config = create_docker_config(image_repo, user, password)
    create_docker_config_secret(namespace, image_pull_secret, docker_config)

    return image_repo, image_pull_secret

def prompt_for_keycloak(namespace, keycloak_secret, postgresql_secret):
    """Prompt for existing Keycloak secrets or create them if they don't exist"""

    if click.confirm('Do you have an existing keycloak secret'):
        keycloak_secret = prompt_for_existing_secret()
    else:
        admin_password = click.prompt('Please enter the Keycloak Admin password (input hidden)', hide_input=True)
        management_password = click.prompt('Please enter the Keycloak WildFly Management password (input hidden)', hide_input=True)
        data = {
            'admin-password': base64.b64encode(admin_password.encode()).decode('ascii'),
            'management-password': base64.b64encode(management_password.encode()).decode('ascii')
        }
        create_secret(namespace,keycloak_secret,'Opaque',data=data)

    if click.confirm('Do you have an existing keycloak postgresql secret'):
        postgresql_secret = prompt_for_existing_secret()
    else:
        postgresql_postgres_password = click.prompt('Please enter the Postgresql postgres password (input hidden)', hide_input=True)
        postgresql_password = click.prompt('Please enter the Postgresql user password (input hidden)', hide_input=True)
        data = {
            'postgresql-postgres-password': base64.b64encode(postgresql_postgres_password.encode()).decode('ascii'),
            'postgresql-password': base64.b64encode(postgresql_password.encode()).decode('ascii')
        }
        create_secret(namespace,postgresql_secret,'Opaque',data=data)

    return keycloak_secret, postgresql_secret

def prompt_for_ingress_cert(namespace, ingress_cert_secret):
    if click.confirm('Do you want to provide a self-managed cert for the ingress'):
        ingress_self_managed = True
        if click.confirm('Do you have an existing secret containing the cert for the ingress'):
            ingress_cert_secret = prompt_for_existing_secret()
        else:
            path_to_cert = click.prompt('Please enter the path to your TLS certificate')
            with open(path_to_cert, 'r') as cert_file:
                cert_data = cert_file.read()
                cert = x509.load_pem_x509_certificate(cert_data.encode(), backend=default_backend())

            path_to_key = click.prompt('Please enter the path to your TLS private key')
            with open(path_to_key, 'r') as key_file:
                key_data = key_file.read()
                key = serialization.load_pem_private_key(key_data.encode(), password=None, backend=default_backend())

            create_tls_secret(namespace, ingress_cert_secret, cert, key)
    else:
        ingress_self_managed = False

    return ingress_self_managed, ingress_cert_secret

def create_docker_config(image_repo, user, password):
    """Output the .dockerconfigjson format given a repo, username and password"""
    config = {
        'auths': {
            image_repo : {
                'username': user,
                'password': password,
                'auth': base64.b64encode(f'{user}:{password}'.encode()).decode('ascii')
            }
        }
    }

    return config

def prompt_for_existing_secret():
    return click.prompt('Please enter the name of the existing secret')

def check_existing_docker_config(image_repo, file_path):
    """Check local .docker/config.json for repo credentials"""
    log.debug(f'Checking {file_path} for existing credentials for the repository {image_repo}')
    try:
        with open(file_path, 'r') as f:
            config = json.loads(f.read())

        if image_repo in config['auths']:
            return config['auths'][image_repo]
    except FileNotFoundError:
        pass

    return None

def create_license_secret(namespace, name, filepath):
    """Create a KX license secret in a given namespace"""

    with open(filepath, 'rb') as license_file:
        encoded_license = base64.b64encode(license_file.read())

    string_data = {
        'license': encoded_license.decode('ascii')
    }

    return create_secret(
        namespace=namespace,
        name=name,
        secret_type='Opaque',
        string_data=string_data
    )

def create_docker_config_secret(namespace, name, docker_config):
    """Create a KX a Docker config secret in a given namespace"""
    docker_config = json.dumps(docker_config).encode()
    data = {
        '.dockerconfigjson': base64.b64encode(docker_config).decode('ascii')
    }

    return create_secret(
        namespace=namespace,
        name=name,
        secret_type='kubernetes.io/dockerconfigjson',
        data=data
    )

def create_tls_secret(namespace, name, cert, key):
    """Create a TLS secret in a given namespace from a cert and private key"""

    # the private key must be unencrypted for a k8s secret
    key_string = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_string = cert.public_bytes(serialization.Encoding.PEM)

    data = {
        'tls.key': base64.b64encode(key_string).decode('ascii'),
        'tls.crt': base64.b64encode(cert_string).decode('ascii')
    }

    return create_secret(
        namespace,
        name=name,
        secret_type='kubernetes.io/tls',
        data=data
    )

def create_secret(namespace, name, secret_type, data=None, string_data=None):
    """Helper function to create a Kubernetes secret"""
    log.debug(f'Creating secret called {name} with type {secret_type} in namespace {namespace}')

    secret = get_secret_body(name, secret_type, data, string_data)
    common.load_kube_config()
    try:
        k8s.client.CoreV1Api().create_namespaced_secret(namespace, body=secret)
    except k8s.client.rest.ApiException as exception:
        log.error(f'Exception when trying to create secret {exception}')
        sys.exit(1)

    click.echo(f'Secret {name} successfully created')

def get_secret_body(name, secret_type, data=None, string_data=None):
    """Create the body for a request to create_namespaced_secret"""
    secret = k8s.client.V1Secret()
    secret.metadata = k8s.client.V1ObjectMeta(name=name)
    secret.type = secret_type

    if data:
        secret.data = data
    if string_data:
        secret.string_data = string_data

    return secret

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
        issuer_name = subject,
        subject_name = subject,
        public_key = private_key.public_key(),
        serial_number = x509.random_serial_number(),
        not_valid_before = datetime.datetime.utcnow(),
        not_valid_after = datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    )

    # This must be set on the generated cert in order of it to be a valid Issuer in kubernetes
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()), critical=False)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)

    return builder.sign(private_key, hashes.SHA256(), default_backend())

def helm_add_repo(repo, url, username, password):
    """Call 'helm repo add' using subprocess.run"""
    log.debug('Attempting to call: helm repo add --username {username} --password {len(password)*"*" {repo} {url}')
    try:
        subprocess.run(['helm', 'repo', 'add', '--username', username, '--password', password, repo, url], check=True)
    except subprocess.CalledProcessError:
        # Pass here so that the password isn't printed in the log
        pass

def helm_install(release, chart, values_file, version=None, namespace=None):
    """Call 'helm install' using subprocess.run"""

    click.echo(f'Installing chart {chart} with values file from {values_file}')

    base_command = ['helm', 'install', '-f', values_file, release, chart]

    if version:
        base_command = base_command + ['--version', version]

    if namespace:
        base_command = base_command + ['--namespace', namespace]
        create_namespace(namespace)

    try:
        log.debug('Install command {base_command}')
        subprocess.run(base_command, check=True)
    except subprocess.CalledProcessError as e:
        click.echo(e)

def create_namespace(name):
    common.load_kube_config()
    api = k8s.client.CoreV1Api()
    ns = k8s.client.V1Namespace()
    ns.metadata = k8s.client.V1ObjectMeta(name=name)
    try:
        api_response = api.create_namespace(ns)
    except k8s.client.rest.ApiException as exception:
        if exception.status == 409:
            pass
        else:
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
        if exception.status == 409:
            pass
        else:
            log.error(f'Exception when trying to create secret {exception}')
            sys.exit(1)

def prompt_for_client_secret(client_name):
    if click.confirm(f'Do you want to set a secret for the {client_name} service account explicity'):
        client_secret = click.prompt('Please enter the secret (input hidden)', hide_input=True)
    else:
        click.echo(f'Randomly generating client secret for {client_name} and setting in values file, record this value for reuse during upgrade')
        client_secret = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(10))

    return client_secret

