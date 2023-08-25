import configparser
import os
from pathlib import Path

import click

from kxi import DeploymentType
from kxicli import phrases
from kxicli import common

config_dir_path = Path.home() / '.insights'
config_dir = str(config_dir_path)
config_file = str(config_dir_path / 'cli-config')

config = configparser.ConfigParser()


def load_config(profile):
    """Load a configuration profile from the config file"""
    global config

    config = configparser.ConfigParser(default_section=profile)
    config.optionxform = str
    config.read(config_file)


def append_config(profile, name, value):
    """Append an option to the configuration for a specific profile"""
    click.echo(phrases.persist_config.format(name=name, file=config_file))

    global config

    if profile not in config:
        config[profile] = {}

    os.makedirs(config_dir, exist_ok=True)
    with open(config_file, 'w+') as f:
        config[profile][name] = value
        config.write(f)


def update_config(profile, name, value):
    """Set the configuration for a specific profile if it has changed"""

    if not config.has_option(profile, name) or config.has_option(profile, name) and config.get(profile, name) != value:
        append_config(profile, name, value)


def set_config(profile):
    """Set the configuration for a specific profile"""
    global config

    if not profile in config:
        config[profile] = {}

    os.makedirs(config_dir, exist_ok=True)
    config[profile]['usage'] = click.prompt(
        'Profile type',
        type=click.Choice([DeploymentType.ENTERPRISE.value, DeploymentType.MICROSERVICES.value]),
        default=config.get(profile, 'usage', fallback=DeploymentType.ENTERPRISE))

    config[profile]['hostname'] = click.prompt(
        'Hostname',
        type=str,
        default=config.get(profile, 'hostname', fallback=''))

    if config[profile]['usage'] == DeploymentType.ENTERPRISE:
        config[profile]['namespace'] = click.prompt(
            'Namespace',
            type=str,
            default=config.get(profile, 'namespace', fallback=''))

        key = 'auth.serviceaccount.id'
        config[profile][key] = click.prompt(
            'Service account ID',
            type=str,
            default=config.get(profile, key, fallback=''))

        if len(config[profile][key]) > 0:
            config[profile]['auth.serviceaccount.secret'] = common.enter_password('Service account Secret (input hidden)')

    elif config[profile]['usage'] == DeploymentType.MICROSERVICES:
        config[profile]['tp_port'] = click.prompt(
            'TP Port',
            type=str,
            default=config.get(profile, 'tp_port', fallback=''))

    with open(config_file, 'w+') as f:
        config.write(f)
