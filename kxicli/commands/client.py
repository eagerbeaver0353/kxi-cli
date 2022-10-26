import json
import sys

import click
import requests

from kxicli import common
from kxicli import log


@click.group()
def client():
    """Commands for interacting with clients"""


@client.command()
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
@click.option('--name', required=True, help='Name of client to enrol')
@click.option('--insert-topic', required=True, help='Topic to insert data on')
@click.option('--client-id', default=lambda: common.get_default_val('client.id'),
              help='Client ID to request an access token with')
@click.option('--client-secret', default=lambda: common.get_default_val('client.secret'),
              help='Client secret to request access token')
@click.option('--realm', default=lambda: common.get_default_val('realm'), help=common.get_help_text('realm'))
def enrol(hostname, name, insert_topic, client_id, client_secret, realm):
    """Enrol a client in the system"""
    token = common.get_access_token(hostname, client_id, client_secret, realm)
    url = f'{hostname}/clientcontroller/enrol'
    headers = {
        'Authorization': f'Bearer {token}'
    }
    payload = {
        'name': name,
        'topics': {
            'insert': insert_topic,
            'query': 'requests'
        }
    }

    r = requests.post(url, headers=headers, json=payload)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        raise click.ClickException('Failed to enrol client')


@client.command()
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
@click.option('--name', required=True, help='Name of the client to remove')
@click.option('--client-id', default=lambda: common.get_default_val('client.id'),
              help='Client ID to request an access token with')
@click.option('--client-secret', default=lambda: common.get_default_val('client.secret'),
              help='Client secret to request access token with')
@click.option('--realm', default=lambda: common.get_default_val('realm'), help=common.get_help_text('realm'))
def remove(hostname, name, client_id, client_secret, realm):
    """Remove a client from the system"""
    token = common.get_access_token(hostname, client_id, client_secret, realm)
    url = f'{hostname}/clientcontroller/leave'
    headers = {
        'Authorization': f'Bearer {token}'
    }
    payload = {
        'name': name
    }

    r = requests.post(url, headers=headers, json=payload)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        raise click.ClickException('Failed to remove client')


@client.command()
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
@click.option('--uid', required=True, help='Client UID to request info for')
def info(hostname, uid):
    """Get certs and endpoints for a client"""
    url = f'{hostname}/informationservice/details/{uid}'
    r = requests.get(url)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        raise click.ClickException('Failed to get client info')


@client.command('list')
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
@click.option('--realm', default=lambda: common.get_default_val('realm'), help=common.get_help_text('realm'))
@click.option('--username', required=True, help='Keycloak admin username')
@click.option('--password', required=True, help='Keycloak admin password')
def list_clients(hostname, realm, username, password):
    """List Keycloak clients in the system"""
    token = common.get_admin_token(hostname, username, password)
    url = f'{hostname}/auth/admin/realms/{realm}/clients'
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }

    r = requests.get(url, headers=headers)
    if r:
        click.echo(json.dumps(r.json(), indent=2))
    else:
        raise click.ClickException('Failed to list clients')
