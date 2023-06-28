import click
from kxi import DeploymentType
from kxicli import config
from kxicli.cli_group import cli



@cli.command(usage=[DeploymentType.MICROSERVICES, DeploymentType.ENTERPRISE])
@click.option('--profile', default='default', help='Name of profile to configure.')
def configure(profile):
    """Configure the CLI"""
    config.set_config(profile)
    click.echo(f'CLI successfully configured, configuration stored in {config.config_file}')
