import os
import sys

import click
import pkg_resources

from kxicli import config
from kxicli import log
from kxicli.commands import client, assembly, auth, install, package, azure, azure_idp, user

CLI_VERSION = pkg_resources.require('kxicli')[0].version
PYTHON_VERSION = f'{sys.version_info.major}.{sys.version_info.minor}'
PKG_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_MSG = f'%(prog)s, version %(version)s from {PKG_DIR} (Python {PYTHON_VERSION})'


@click.group()
@click.version_option(CLI_VERSION, message=VERSION_MSG)
@click.option('--debug', is_flag=True, default=False, help='Enable debug logging.')
@click.option('--profile', default='default', help='Name of configuration profile to use.')
@click.pass_context
def cli(ctx, debug, profile):
    """kdb Insights Enterprise CLI"""
    ctx.obj = {}
    if debug:
        ctx.obj["debug"] = True
        log.GLOBAL_DEBUG_LOG = True
        log.debug(f'Version {CLI_VERSION}')
        log.debug('Enabled global debug logging')

    config.load_config(profile)
    if profile not in config.config and ctx.invoked_subcommand != 'configure':
        config.set_config(profile)

    ctx.obj["kxi_cli_profile"] = profile


@click.command()
@click.option('--profile', default='default', help='Name of profile to configure.')
def configure(profile):
    """Configure the CLI"""
    config.set_config(profile)
    click.echo(f'CLI successfully configured, configuration stored in {config.config_file}')


cli.add_command(client.client)
cli.add_command(assembly.assembly)
cli.add_command(auth.auth)
cli.add_command(azure.azure)
cli.add_command(azure_idp.idp)
cli.add_command(azure_idp.mapper)
cli.add_command(install.install)
cli.add_command(configure)
cli.add_command(package.package)
cli.add_command(user.user)

if __name__ == '__main__':
    cli()  # pylint: disable=no-value-for-parameter
