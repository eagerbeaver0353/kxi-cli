import os
import click
import kubernetes as k8s

from kxi import config
from kxi import log
from kxi.commands import client, assembly, query, auth, install

CLI_VERSION = '0.1.0'

# If running locally get config from kube-config
# If we're in the cluster use the cluster config
if os.environ.get('KUBERNETES_SERVICE_HOST','') == '':
    k8s.config.load_kube_config()
else:
    k8s.config.load_incluster_config()

@click.group()
@click.option('--debug', is_flag=True, default=False, help='Enable debug logging.')
@click.option('--profile', default='default', help='Name of configuration profile to use.')
@click.pass_context
def cli(ctx, debug, profile):
    """KX Insights test CLI"""
    if debug:
        log.GLOBAL_DEBUG_LOG=True
        log.debug(f'Version {CLI_VERSION}')
        log.debug('Enabled global debug logging')

    config.load_config(profile)
    if not profile in config.config and not ctx.invoked_subcommand == 'configure':
        config.set_config(profile)

@click.command()
@click.option('--profile', default='default', help='Name of profile to configure.')
def configure(profile):
    """Configure the CLI"""
    config.set_config(profile)
    click.echo(f'CLI successfully configured, configuration stored in {config.config_file}')

@click.command()
def version():
    """Print the version of the CLI"""
    click.echo(f'Version {CLI_VERSION}')

cli.add_command(client.client)
cli.add_command(assembly.assembly)
cli.add_command(query.query)
cli.add_command(auth.auth)
cli.add_command(install.install)
cli.add_command(version)
cli.add_command(configure)
