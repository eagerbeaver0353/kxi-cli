import click
from kxi import common

@click.group()
def auth():
    """Authentication and authorization commands"""

@auth.command()
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
@click.option('--client-id', default=lambda: common.get_default_val('client.id'), help='Client ID to request access token for')
@click.option('--client-secret', default=lambda: common.get_default_val('client.secret'), help='Client secret to request access token')
def get_access_token(hostname, client_id, client_secret):
    """Get an access token for a client id and secret"""
    click.echo(common.get_access_token(hostname, client_id, client_secret))

@auth.command()
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
def get_admin_token(hostname):
    """Get an admin access token for the Keycloak Admin API"""
    click.echo(common.get_admin_token(hostname))
