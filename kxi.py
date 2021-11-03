import time
import random
import sys
import json
import datetime
import os
import configparser
import click
import requests
import kubernetes as k8s
from tabulate import tabulate

GLOBAL_DEBUG_LOG = False
CLI_VERSION = '0.1.0'
config_dir = f"{os.environ['HOME']}/.insights"
config_file = f"{config_dir}/cli-config"
# Initialized to a config parser once the profile is known
config = None

# If running locally get config from kube-config
# If we're in the cluster use the cluster config
if os.environ.get('KUBERNETES_SERVICE_HOST','') == '':
    k8s.config.load_kube_config()
else:
    k8s.config.load_incluster_config()

# Internal functions

def _get_default_val(option):
    return config.get(config.default_section, option, fallback='')

def _log_debug(msg):
    if GLOBAL_DEBUG_LOG:
        click.echo(f"{click.style('debug', fg='blue')}={msg}")

def _log_error(msg):
    click.echo(f"{click.style('error', fg='red', bold=True)}={msg}")

def _get_access_token(hostname, client_id, client_secret):
    _log_debug('Requesting access token')
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
    else:
        _log_error('Failed to request access token')
        click.echo(r.text)
        sys.exit(1)

def _assembly_status(namespace, name, print_status=False):
    """Get status of assembly"""
    v1 = k8s.client.CoreV1Api()
    res = v1.list_namespaced_pod(namespace, label_selector=f'insights.kx.com/app={name}')

    is_running = [ pod.status.phase == 'Running' for pod in res.items ]

    if print_status:
        click.echo('POD\tSTATUS')
        for pod in res.items:
            click.echo(f'{pod.metadata.name}: {pod.status.phase}')

    if all(is_running):
        return True
    else:
        return False

def _get_admin_token(hostname):
    _log_debug('Requesting admin access token')
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
    else:
        _log_error('Failed to request admin access token')
        click.echo(r.text)
        sys.exit(1)

def _configure(profile):
    global config

    if not profile in config:
        config[profile] = {}

    os.makedirs(config_dir, exist_ok=True)
    with open(config_file, 'w+') as f:
        config[profile]['hostname'] = click.prompt(
            'Hostname',
            type=str,
            default=config.get(profile, 'hostname', fallback=''))

        config[profile]['namespace'] = click.prompt(
            'Namespace',
            type=str,
            default=config.get(profile, 'namespace', fallback=''))

        config[profile]['client.id'] = click.prompt(
            'Client ID',
            type=str,
            default=config.get(profile, 'client.id', fallback=''))

        config[profile]['client.secret'] =  click.prompt(
            'Client Secret (input hidden)',
            type=str,
            hide_input=True
            )

        config.write(f)

    click.echo(f'CLI successfully configured, configuration stored in {config_file}')

# CLI command functions

# Generic help text dictionary for commands
help_text = {}
help_text['hostname'] = 'Hostname of Insights deployment.'

@click.group()
@click.option('--debug', is_flag=True, default=False, help='Enable debug logging.')
@click.option('--profile', default='default', help='Name of configuration profile to use.')
@click.pass_context
def cli(ctx, debug, profile):
    """KX Insights test CLI"""
    global GLOBAL_DEBUG_LOG
    global config

    if debug:
        GLOBAL_DEBUG_LOG=True
        _log_debug(f'Version {CLI_VERSION}')
        _log_debug('Enabled global debug logging')

    config = configparser.ConfigParser(default_section=profile)
    config.read(config_file)
    if not profile in config and not ctx.invoked_subcommand == 'configure':
        _configure(profile)

@cli.command()
@click.option('--profile', default='default', help='Name of profile to configure.')
def configure(profile):
    """Configure the CLI"""
    _configure(profile)

@cli.command()
def version():
    """Print the version of the CLI"""
    click.echo(f'Version {CLI_VERSION}')

@cli.command()
@click.option('--hostname', default=lambda: _get_default_val('hostname'), help=help_text['hostname'])
@click.option('--client-id', default=lambda: _get_default_val('client.id'), help='Client ID to request access token for')
@click.option('--client-secret', default=lambda: _get_default_val('client.secret'), help='Client secret to request access token')
def get_access_token(hostname, client_id, client_secret):
    """Get an access token for a client id and secret"""
    click.echo(_get_access_token(hostname, client_id, client_secret))

@cli.command()
@click.option('--hostname', default=lambda: _get_default_val('hostname'), help=help_text['hostname'])
def get_admin_token(hostname):
    """Get an admin access token for the Keycloak Admin API"""
    click.echo(_get_admin_token(hostname))

@cli.command()
@click.option('--hostname', default=lambda: _get_default_val('hostname'), help=help_text['hostname'])
@click.option('--client-id', default=lambda: _get_default_val('client.id'), help='Client ID to enrol')
@click.option('--client-secret', default=lambda: _get_default_val('client.secret'), help='Client secret to request access token')
def client_enrol(hostname, client_id, client_secret):
    """Enrol a client in the system"""
    token = _get_access_token(hostname, client_id, client_secret)
    url = hostname + '/clientcontroller/enrol'
    headers = {
        'Authorization': 'Bearer ' + token
    }
    payload = {
        'name': client_id,
        'topics': {
            'insert': 'data',
            'query': 'requests'
        }
    }

    r = requests.post(url, headers=headers, json=payload)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        _log_error(r.text)
        sys.exit(1)

@cli.command()
@click.option('--hostname', default=lambda: _get_default_val('hostname'), help=help_text['hostname'])
@click.option('--client-id', default=lambda: _get_default_val('client.id'), help='Client ID to remove')
@click.option('--client-secret', default=lambda: _get_default_val('client.secret'), help='Client secret to request access token with')
def client_remove(hostname, client_id, client_secret):
    """Remove a client from the system"""
    token = _get_access_token(hostname, client_id, client_secret)
    url = hostname + '/clientcontroller/leave'
    headers = {
        'Authorization': 'Bearer ' + token
    }
    payload = {
        'name': client_id
    }

    r = requests.post(url, headers=headers, json=payload)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        _log_error(r.text)
        sys.exit(1)

@cli.command()
@click.option('--hostname', default=lambda: _get_default_val('hostname'), help=help_text['hostname'])
@click.option('--uid', required=True, help='Client UID to request info for')
def client_info(hostname, uid):
    """Get certs and endpoints for a client"""
    url = hostname + '/informationservice/details/' + uid
    r = requests.get(url)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        _log_error(r.text)
        sys.exit(1)

@cli.command()
@click.option('--hostname', default=lambda: _get_default_val('hostname'), help=help_text['hostname'])
def client_list(hostname):
    """List Keycloak clients in the system"""
    token = _get_admin_token(hostname)
    url = hostname + '/auth/admin/realms/insights/clients'
    headers = {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json'
    }

    r = requests.get(url, headers=headers)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        _log_error(r.text)
        sys.exit(1)

@cli.command()
@click.option('--hostname', default=lambda: _get_default_val('hostname'), help=help_text['hostname'])
@click.option('--client-id', default=lambda: _get_default_val('client.id'), help='Client ID to query with')
@click.option('--client-secret', default=lambda: _get_default_val('client.secret'), help='Client secret to request access token')
@click.option('--table', required=True, help='Name of the table to query')
@click.option('--counts', is_flag=True, help='Only return the column count and row count of the returned data')
def query(hostname, client_id, client_secret, table, counts):
    """Query a table for today's data"""
    token = _get_access_token(hostname, client_id, client_secret)
    url = hostname + '/servicegateway/kxi/getData'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token,
        'Accepted': 'application/json'
    }

    today = datetime.datetime.today().strftime('%Y.%m.%d')
    payload = {
        'table': table,
        'startTS': today + 'D00:00:00.000000000',
        'endTS': today + 'D23:59:59.999999999',
        'region': 'Canada'
    }

    _log_debug(f'Query payload={json.dumps(payload, indent=2)}')
    r = requests.post(url, headers=headers, json=payload)
    if r and 'application/json' in r.headers.get('Content-Type'):
        payload = r.json()[1]

        if [] == payload:
            click.echo('Empty payload')
            sys.exit(0)
        elif counts:
            click.echo(f"{len(payload['x'])} column(s), {len(payload['y'][0])} row(s)")
        else:
            click.echo(tabulate(zip(*payload['y']), headers=payload['x']))
            sys.exit(0)
    else:
        _log_error(r.text)
        sys.exit(1)

@cli.command()
@click.option('--namespace', default=lambda: _get_default_val('namespace'), help='Namespace to create assembly in')
@click.option('--filepath', required=True, help='Path to JSON assembly file')
@click.option('--wait', is_flag=True, help='Wait for all pods to be running')
def create_assembly(namespace, filepath, wait):
    """Create an assembly given an assembly file"""
    click.echo(f'Submitting assembly from {filepath}')

    api = k8s.client.CustomObjectsApi()

    with open(filepath) as f:
        body = json.load(f)

    api.create_namespaced_custom_object(
        group='insights.kx.com',
        version='v1alpha1',
        namespace=namespace,
        plural='assemblies',
        body=body,
    )

    click.echo(f'Custom assembly resource {body["metadata"]["name"]} created!')

    if wait:
        with click.progressbar(range(10), label='Waiting for all pods to be running') as bar:
            for n in bar:
                time.sleep((2 ** n) + (random.randint(0, 1000) / 1000))
                if _assembly_status(namespace, body['metadata']['name']):
                    sys.exit(0)

@cli.command()
@click.option('--namespace', default=lambda: _get_default_val('namespace'), help='Namespace that the assembly is in')
@click.option('--name', required=True, help='Name of the assembly get the status of')
def assembly_status(namespace, name):
    """Print status of the assembly"""
    if _assembly_status(namespace, name, print_status=True):
        sys.exit(0)
    else:
        sys.exit(1)

@cli.command()
@click.option('--namespace', default=lambda: _get_default_val('namespace'), help='Namespace that the assembly is in')
@click.option('--name', required=True, help='Name of the assembly to delete')
@click.option('--wait', is_flag=True, help='Wait for all pods to be deleted')
@click.option('--force', is_flag=True, help='Delete assembly without getting confirmation')
def delete_assembly(namespace, name, wait, force):
    """Deletes an assembly given its name"""
    click.echo(f'Deleting assembly {name}')

    if not force:
        if click.confirm(f'Are you sure you want to delete {name}'):
            pass
        else:
            click.echo(f'Not deleting assembly {name}')
            sys.exit(0)

    api = k8s.client.CustomObjectsApi()
    try:
        api.delete_namespaced_custom_object(
            group='insights.kx.com',
            version='v1alpha1',
            namespace=namespace,
            plural='assemblies',
            name=name,
            )
    except k8s.client.rest.ApiException as exception:
        if exception.status == 404:
            click.echo(f'Ignoring delete, {name} not found')
            sys.exit(0)
        else:
            click.echo(f'Exception when calling CustomObjectsApi->delete_namespaced_custom_object: {exception}\n')

    if wait:
        v1 = k8s.client.CoreV1Api()
        with click.progressbar(range(10), label='Waiting for all pods to be deleted') as bar:
            for n in bar:
                time.sleep((2 ** n) + (random.randint(0, 1000) / 1000))
                res = v1.list_namespaced_pod(namespace, label_selector=f'insights.kx.com/app={name}')
                if [] == res.items:
                    sys.exit(0)

        _log_error('Assembly was not deleted in time, exiting')
        sys.exit(1)
