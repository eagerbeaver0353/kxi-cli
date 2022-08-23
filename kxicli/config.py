import configparser
import os
from pathlib import Path

import click

from kxicli import phrases
from kxicli import common

config_dir_path = Path.home() / '.insights'
config_dir = str(config_dir_path)
config_file = str(config_dir_path / 'cli-config')

config = None


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


def set_config(profile):
    """Set the configuration for a specific profile"""
    global config

    if not profile in config:
        config[profile] = {}

    os.makedirs(config_dir, exist_ok=True)
    config[profile]['hostname'] = click.prompt(
        'Hostname',
        type=str,
        default=config.get(profile, 'hostname', fallback=''))

    config[profile]['namespace'] = click.prompt(
        'Namespace',
        type=str,
        default=config.get(profile, 'namespace', fallback=''))

    config[profile]['client.id'] = click.prompt(
        'Client ID',
        type=str,
        default=config.get(profile, 'client.id', fallback=''))

    config[profile]['client.secret'] = common.enter_password('Client Secret (input hidden)')

    with open(config_file, 'w+') as f:
        config.write(f)
