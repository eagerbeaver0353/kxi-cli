import click

from kxicli import common
from kxicli import options
from kxicli.commands.common import arg
from kxicli.cli_group import ProfileAwareGroup, cli

@cli.group(cls=ProfileAwareGroup)
def auth():
    """Authentication and authorization commands"""


@auth.command()
@arg.hostname()
@click.option('--client-id', default=lambda: common.get_default_val('client.id'),
              help='Client ID to request access token for')
@click.option('--client-secret', default=lambda: common.get_default_val('client.secret'),
              help='Client secret to request access token')
@click.option('--realm', default=lambda: common.get_default_val('realm'), help=common.get_help_text('realm'))
def get_access_token(hostname, client_id, client_secret, realm):
    """Get an access token for a client id and secret"""
    hostname = common.sanitize_hostname(options.hostname.prompt(hostname))
    click.echo(common.get_access_token(hostname, client_id, client_secret, realm))


@auth.command()
@arg.hostname()
@click.option('--username', required=True, help='Keycloak admin username')
@click.option('--password', required=True, help='Keycloak admin password')
def get_admin_token(hostname, username, password):
    """Get an admin access token for the Keycloak Admin API"""
    hostname = common.sanitize_hostname(options.hostname.prompt(hostname))
    click.echo(common.get_admin_token(hostname, username, password))
