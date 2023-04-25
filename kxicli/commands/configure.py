import click
from kxicli import config

@click.command()
@click.option('--profile', default='default', help='Name of profile to configure.')
def configure(profile):
    """Configure the CLI"""
    config.set_config(profile)
    click.echo(f'CLI successfully configured, configuration stored in {config.config_file}')
