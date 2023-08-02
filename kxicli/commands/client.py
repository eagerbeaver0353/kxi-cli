import json
import sys

import click
import requests
from requests.exceptions import HTTPError

from kxicli import common
from kxicli import log
from kxicli import options
from kxicli.commands.common import arg
from kxicli.cli_group import cli, ProfileAwareGroup

@cli.group(cls=ProfileAwareGroup)
def client():
    """Commands for interacting with clients"""


@client.command()
@arg.hostname()
@click.option('--name', required=True, help='Name of client to enrol')
@click.option('--insert-topic', required=True, help='Topic to insert data on')
@click.option('--client-id', default=lambda: common.get_default_val('client.id'),
              help='Client ID to request an access token with')
@click.option('--client-secret', default=lambda: common.get_default_val('client.secret'),
              help='Client secret to request access token')
@click.option('--realm', default=lambda: common.get_default_val('realm'), help=common.get_help_text('realm'))

def enrol(hostname, name, insert_topic, client_id, client_secret, realm):
    """Enrol a client in the system"""
    hostname = common.sanitize_hostname(options.hostname.prompt(hostname))
    token = common.get_access_token(hostname, client_id, client_secret, realm)
    url = f'https://{hostname}/clientcontroller/enrol'
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

    try:
        r = requests.post(url, headers=headers, json=payload)
        r.raise_for_status()
        click.echo(json.dumps(r.json(), indent=2))
    except HTTPError as e:
        common.handle_http_exception(e, "Failed to enrol client: ")


@client.command()
@arg.hostname()
@click.option('--name', required=True, help='Name of the client to remove')
@click.option('--client-id', default=lambda: common.get_default_val('client.id'),
              help='Client ID to request an access token with')
@click.option('--client-secret', default=lambda: common.get_default_val('client.secret'),
              help='Client secret to request access token with')
@click.option('--realm', default=lambda: common.get_default_val('realm'), help=common.get_help_text('realm'))
def remove(hostname, name, client_id, client_secret, realm):
    """Remove a client from the system"""
    hostname = common.sanitize_hostname(options.hostname.prompt(hostname))
    token = common.get_access_token(hostname, client_id, client_secret, realm)
    url = f'https://{hostname}/clientcontroller/leave'
    headers = {
        'Authorization': f'Bearer {token}'
    }
    payload = {
        'name': name
    }

    try:
        r = requests.post(url, headers=headers, json=payload)
        r.raise_for_status()
        click.echo(json.dumps(r.json(), indent=2))
    except HTTPError as e:
        common.handle_http_exception(e, "Failed to remove client: ")

@client.command()
@arg.hostname()
@click.option('--uid', required=True, help='Client UID to request info for')
def info(hostname, uid):
    """Get certs and endpoints for a client"""
    hostname = common.sanitize_hostname(options.hostname.prompt(hostname))
    url = f'https://{hostname}/informationservice/details/{uid}'
   
    try:
        r = requests.get(url)
        r.raise_for_status()
        click.echo(json.dumps(r.json(), indent=2))
    except HTTPError as e:
        common.handle_http_exception(e, "Failed to get client info: ")


@client.command('list', hidden=True, deprecated=True)
@arg.hostname()
@click.option('--realm', default=lambda: common.get_default_val('realm'), help=common.get_help_text('realm'))
@click.option('--username', required=True, help='Keycloak admin username')
@click.option('--password', required=True, help='Keycloak admin password')
def list_clients(hostname, realm, username, password):
    """List Keycloak clients in the system"""
    hostname = common.sanitize_hostname(options.hostname.prompt(hostname))
    token = common.get_admin_token(hostname, username, password)
    url = f'https://{hostname}/auth/admin/realms/{realm}/clients'
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }

    try:
        r = requests.get(url, headers=headers)
        r.raise_for_status()
        click.echo(json.dumps(r.json(), indent=2))
    except HTTPError as e:
        common.handle_http_exception(e, "Failed to list clients: ")