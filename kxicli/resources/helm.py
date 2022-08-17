import subprocess
import click

from kxicli import log


def env():
    log.debug('Attempting to call: helm env')
    try:
        out = subprocess.check_output(['helm', 'env'])
    except subprocess.CalledProcessError as e:
        raise click.ClickException(e)

    data = {}
    # output line are in the format
    # 'HELM_BIN="helm"'
    # so split on newline, partition on equals and strip the extra quotes
    # to format as a dictionary
    for line in out.decode().split('\n'):
        k,v = line.partition('=')[::2]
        data[k] = v.strip('"')

    return data

def fetch(repo, chart_name, destination=None, version=None):
    cmd = ['helm', 'fetch', f'{repo}/{chart_name}']

    if destination is not None:
        cmd = cmd + ['--destination', destination]

    if version is not None:
        cmd = cmd + ['--version', version]

    try:
        out = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        raise click.ClickException(e)

    return out

def get_repository_cache():
    data = env()
    if 'HELM_REPOSITORY_CACHE' in data:
        cache = data['HELM_REPOSITORY_CACHE']
    else:
        raise click.ClickException('Could not find HELM_REPOSITORY_CACHE in "helm env" output')

    return cache
