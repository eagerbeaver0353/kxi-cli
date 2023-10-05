import click

from kxicli import common
from kxicli import options
from kxicli.commands.common import arg
from kxicli.cli_group import ProfileAwareGroup, cli
from kxicli.resources import auth as auth_lib


@cli.group(cls=ProfileAwareGroup)
def auth():
    """Authentication and authorization commands"""


@auth.command(hidden=True, deprecated=True)
@arg.hostname()
@arg.client_id()
@arg.client_secret()
@arg.realm()
@click.option('--redirect-host', default='localhost', help='Web host to serve token request after login')
@click.option('--redirect-port', default=4200, help='Port to serve token request after login')
@arg.serviceaccount_id()
@arg.serviceaccount_secret()
@arg.force_code()
def get_access_token(hostname, client_id, client_secret, realm,
                     redirect_host, redirect_port,
                     serviceaccount_id, serviceaccount_secret, force_code):
    """Get an access token for a client id and secret"""
    host = options.get_hostname()
    click.echo(auth_lib.get_token(host, realm, redirect_host, redirect_port, force_code))

@auth.command()
def print_token():
    """Get an access token for a client id and secret"""
    cache_file = options.cache_file.retrieve_value()

    token, _, active = auth_lib.check_cached_token_active(cache_file)
    if active:
        click.echo(token['access_token'])
    else:
        click.echo(f'No valid token found in the file: {cache_file}')

@auth.command()
@arg.hostname()
@click.option('--username', required=True, help='Keycloak admin username')
@click.option('--password', required=True, help='Keycloak admin password')
def get_admin_token(hostname, username, password):
    """Get an admin access token for the Keycloak Admin API"""
    host = options.get_hostname()
    click.echo(auth_lib.get_admin_token(host, username, password))


@auth.command()
@arg.hostname()
@arg.realm()
@click.option('--redirect-host', default='localhost', help='Web host to serve token request after login')
@click.option('--redirect-port', default=0, help='Port to serve token request after login')
@arg.serviceaccount()
@arg.client_id()
@arg.client_secret()
@arg.serviceaccount_id()
@arg.serviceaccount_secret()
@arg.force_code()
def login(hostname,
          realm,
          redirect_host,
          redirect_port,
          client_id,
          client_secret,
          serviceaccount,
          serviceaccount_id,
          serviceaccount_secret,
          force_code,
          ):
    """Authenticate as a user or service account"""
    host = options.get_hostname()
    token_type = auth_lib.TokenType.SERVICEACCOUNT if serviceaccount else auth_lib.TokenType.USER
    auth_lib.retrieve_token(host,
                   realm,
                   redirect_host,
                   redirect_port,
                   token_type,
                   force_code,
                   )
