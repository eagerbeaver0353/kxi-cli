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
from kxicli.resources import auth
from kxicli.resources.auth import TokenType
from kxi.client_controller import ClientController, Client
from kxi.auth import CredentialStore
from kxicli.resources import auth as auth_lib

@cli.group(cls=ProfileAwareGroup)
def client():
    """Commands for interacting with clients"""


@client.command()
@arg.hostname()
@click.option('--name', required=True, help='Name of client to enrol')
@click.option('--insert-topic', required=True, help='Topic to insert data on')
@arg.client_id()
@arg.client_secret()
@arg.realm()
def enrol(hostname, name, insert_topic, client_id, client_secret, realm):
    """Enrol a client in the system"""
    host = options.get_hostname()
    client = Client(name = name)    
    client_controller = get_clientcontroller_object(host, realm)
    res = client_controller.enrol(client)
    click.echo(json.dumps(res, indent=2))

@client.command()
@arg.hostname()
@click.option('--name', required=True, help='Name of the client to remove')
@arg.client_id()
@arg.client_secret()
@arg.realm()
def remove(hostname, name, client_id, client_secret, realm):
    """Remove a client from the system"""
    host = options.get_hostname()
    client = Client(name = name)

    client_controller = get_clientcontroller_object(host, realm)
    res = client_controller.leave(client)
    click.echo(json.dumps(res, indent=2))

@client.command()
@arg.hostname()
@click.option('--uid', required=True, help='Client UID to request info for')
def info(hostname, uid):
    """Get certs and endpoints for a client"""
    host = options.get_hostname()
    url = f'https://{host}/informationservice/details/{uid}'
   
    try:
        r = requests.get(url)
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
    host = options.get_hostname()
    token = auth.get_admin_token(host, username, password)
    url = f'https://{host}/auth/admin/realms/{realm}/clients'
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

def get_clientcontroller_object(host, realm):
    store = CredentialStore(name = options.get_profile(), file_path= common.token_cache_file, 
                            file_format= common.token_cache_format)

    grant_type = store.get('grant_type', default=TokenType.SERVICEACCOUNT)
    client_id = options.get_serviceaccount_id()
    
    if grant_type == TokenType.USER:
        client_id = store.get('client_id')

    return ClientController(host, realm=realm,
                    client_id=client_id, grant_type=grant_type, 
                    client_secret = options.get_serviceaccount_secret(), cache=store)