import os
import configparser
import click

config_dir = f"{os.environ['HOME']}/.insights"
config_file = f'{config_dir}/cli-config'

config = None

def load_config(profile):
    """Load a configuration profile from the config file"""
    global config

    config = configparser.ConfigParser(default_section=profile)
    config.read(config_file)

def set_config(profile):
    """Set the configuration for a specific profile"""
    global config

    if not profile in config:
        config[profile] = {}

    os.makedirs(config_dir, exist_ok=True)
    with open(config_file, 'w+') as f:
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

        config[profile]['client.secret'] =  click.prompt(
            'Client Secret (input hidden)',
            type=str,
            hide_input=True
            )

        config.write(f)
