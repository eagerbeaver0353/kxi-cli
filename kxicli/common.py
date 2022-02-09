import sys
import os
import click
import requests
import kubernetes as k8s
from kxicli import config
from kxicli import log

# Help text dictionary for commands
HELP_TEXT = {
    'hostname': 'Hostname of Insights deployment',
    'namespace': 'Kubernetes namespace',
    'chart.repo.name': 'Name for chart repository',
    'chart.repo.url': 'Repository URL to pull charts from',
    'chart.repo.username': 'Username for the chart repository',
    'chart.repo.password': 'Password for the chart repository',
    'license.secret': 'Secret containing kdb+ license',
    'client.cert.secret': 'Secret containing TLS cert and key for client issuer',
    'image.repository': 'Repository to pull images from',
    'image.pullSecret': 'Secret containing credentials for the image repository ',
    'keycloak.secret': 'Secret containing Keycloak admin password',
    'keycloak.postgresqlSecret': 'Secret containing Keycloak postgresql passwords',
    'ingress.host': 'Hostname for the installation',
    'ingress.cert.secret': 'Secret containing self-managed TLS cert and key for the ingress',
    'install.outputFile': 'Name for the generated values file',
    'release.name': 'Release name for the install',
    'guiClientSecret': 'Keycloak client secret for gui service account',
    'operatorClientSecret': 'Keycloak client secret for operator service account'
}

# Default values for commands if needed
DEFAULT_VALUES = {
    'license.secret': 'kxi-license',
    'client.cert.secret': 'kxi-certificate',
    'chart.repo.name': 'kx-insights',
    'chart.repo.url': 'https://nexus.dl.kx.com/repository/kx-insights-charts',
    'image.pullSecret': 'kxi-nexus-pull-secret',
    'image.repository': 'registry.dl.kx.com',
    'keycloak.secret': 'kxi-keycloak',
    'keycloak.postgresqlSecret': 'kxi-postgresql',
    'ingress.cert.secret': 'kxi-ingress-cert',
    'install.outputFile': 'values.yaml',
    'release.name': 'insights'
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
    if config.config.has_option(config.config.default_section, option):
        return config.config.get(config.config.default_section, option)

    if option in DEFAULT_VALUES:
        return DEFAULT_VALUES[option]

    return ''

def get_access_token(hostname, client_id, client_secret):
    """Get Keycloak client access token"""
    log.debug('Requesting access token')
    url = hostname + '/auth/realms/insights/protocol/openid-connect/token'
    headers = {
        'Content-Type' : 'application/x-www-form-urlencoded'
    }
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }

    r = requests.post(url, headers=headers, data=payload)
    if r:
        return r.json()['access_token']

    log.error('Failed to request access token')
    click.echo(r.text)
    sys.exit(1)

def get_admin_token(hostname):
    """Get Keycloak Admin API token from hostname"""
    log.debug('Requesting admin access token')
    url = hostname + '/auth/realms/master/protocol/openid-connect/token'
    headers = {
        'Content-Type' : 'application/x-www-form-urlencoded'
    }

    #TODO: Make these configurable
    payload = {
        'grant_type': 'password',
        'username': 'user',
        'password': 'admin',
        'client_id': 'admin-cli'
    }
    r = requests.post(url, headers=headers, data=payload)
    if r:
        return r.json()['access_token']

    log.error('Failed to request admin access token')
    click.echo(r.text)
    sys.exit(1)

def load_kube_config():
    global CONFIG_ALREADY_LOADED

    if not CONFIG_ALREADY_LOADED:
        k8s.config.load_config()
        CONFIG_ALREADY_LOADED = True

def crd_exists(name):
    load_kube_config()
    api = k8s.client.ApiextensionsV1Api()

    try:
        api.read_custom_resource_definition(name)
        return True
    except k8s.client.rest.ApiException as exception:
        if exception.status == 404:
            return False
        else:
            click.echo(f'Exception when calling ApiextensionsV1Api->list_custom_resource_definition: {exception}')
