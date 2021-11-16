import sys
import json
import click
import requests
from kxi import common
from kxi import log

@click.group()
def client():
    """Commands for interacting with clients"""

@client.command()
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
@click.option('--name', required=True, help='Name of client to enrol')
@click.option('--client-id', default=lambda: common.get_default_val('client.id'), help='Client ID to request an access token with')
@click.option('--client-secret', default=lambda: common.get_default_val('client.secret'), help='Client secret to request access token')
def enrol(hostname, name, client_id, client_secret):
    """Enrol a client in the system"""
    token = common.get_access_token(hostname, client_id, client_secret)
    url = hostname + '/clientcontroller/enrol'
    headers = {
        'Authorization': 'Bearer ' + token
    }
    payload = {
        'name': name,
        'topics': {
            'insert': 'data',
            'query': 'requests'
        }
    }

    r = requests.post(url, headers=headers, json=payload)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        log.error(r.text)
        sys.exit(1)

@client.command()
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
@click.option('--name', required=True, help='Name of the client to remove')
@click.option('--client-id', default=lambda: common.get_default_val('client.id'), help='Client ID to request an access token with')
@click.option('--client-secret', default=lambda: common.get_default_val('client.secret'), help='Client secret to request access token with')
def remove(hostname, name, client_id, client_secret):
    """Remove a client from the system"""
    token = common.get_access_token(hostname, client_id, client_secret)
    url = hostname + '/clientcontroller/leave'
    headers = {
        'Authorization': 'Bearer ' + token
    }
    payload = {
        'name': name
    }

    r = requests.post(url, headers=headers, json=payload)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        log.error(r.text)
        sys.exit(1)

@client.command()
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
@click.option('--uid', required=True, help='Client UID to request info for')
def info(hostname, uid):
    """Get certs and endpoints for a client"""
    url = hostname + '/informationservice/details/' + uid
    r = requests.get(url)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        log.error(r.text)
        sys.exit(1)

@client.command('list')
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
def list_clients(hostname):
    """List Keycloak clients in the system"""
    token = common.get_admin_token(hostname)
    url = hostname + '/auth/admin/realms/insights/clients'
    headers = {
        'Authorization': 'Bearer ' + token,
        'Accept': 'application/json'
    }

    r = requests.get(url, headers=headers)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        log.error(r.text)
        sys.exit(1)
