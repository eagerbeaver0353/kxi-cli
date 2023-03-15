import click
import os
import subprocess
import sys
from functools import lru_cache
from typing import List
import json

import click
from click import ClickException
from packaging.version import Version

from kxicli import log
from kxicli.commands.common.docker import temp_docker_config
from kxicli.commands.common.namespace import create_namespace


class RequiredHelmVersion(Version):
    pass


class LocalHelmVersion(Version):
    pass


minimum_helm_version: str = '3.8.0'
required_helm_version: RequiredHelmVersion = RequiredHelmVersion(version=minimum_helm_version)


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

def fetch(repo, chart_name, destination=None, version=None, docker_config=''):
    cmd = ['helm', 'fetch', f'{repo}/{chart_name}']

    if destination is not None:
        cmd = cmd + ['--destination', destination]

    if version is not None:
        cmd = cmd + ['--version', version]

    try:
        log.debug(f'Upgrade install command {cmd}')
        with temp_docker_config(docker_config) as temp_dir:
            helm_env = os.environ.copy()
            helm_env['DOCKER_CONFIG'] = temp_dir
            out = subprocess.check_output(cmd, env=helm_env)
    except subprocess.CalledProcessError as e:
        raise ClickException(e)


    return out

def get_repository_cache():
    data = env()
    if 'HELM_REPOSITORY_CACHE' in data:
        cache = data['HELM_REPOSITORY_CACHE']
    else:
        raise click.ClickException('Could not find HELM_REPOSITORY_CACHE in "helm env" output')

    return cache


def upgrade_install(
        release: str,
        chart: str,
        args = [],
        docker_config: str = '',
        version: str = None,
        namespace: str = None,
        values_file: str = None,
        values_secret: str = None
) -> subprocess.CompletedProcess:
    """Call 'helm upgrade install' using subprocess.run"""

    base_command = ['helm', 'upgrade', '--install']

    if values_secret:
        base_command = base_command + ['-f', '-']
        input_arg = values_secret
        text_arg = True
    else:
        input_arg=None
        text_arg=None

    if values_file:
        base_command = base_command + ['-f', values_file]

    base_command = base_command + [release, chart]
    base_command = base_command + args    

    version_msg = ''
    if version:
        version_msg = ' version ' + version
        base_command = base_command + ['--version', version]
    if values_file:
        if values_secret:
            click.echo(f'Installing chart {chart}{version_msg} with values from secret and values file from {values_file}')
        else:
            click.echo(f'Installing chart {chart}{version_msg} with values file from {values_file}')
    else:
        if values_secret:
            click.echo(f'Installing chart {chart}{version_msg} with values from secret')
        else:
            raise click.ClickException(f'Must provide one of values file or secret. Exiting install')
            
    if namespace:
        base_command = base_command + ['--namespace', namespace]
        create_namespace(namespace)                
        
    try:
        log.debug(f'Upgrade install command {base_command}')
        with temp_docker_config(docker_config) as temp_dir:
            helm_env = os.environ.copy()
            helm_env['DOCKER_CONFIG'] = temp_dir
            return subprocess.run(base_command, check=True, input=input_arg, text=text_arg, env=helm_env)
    except subprocess.CalledProcessError as e:
        raise ClickException(str(e))


def uninstall(release, namespace=None):
    """Call 'helm uninstall' using subprocess.run"""

    msg = f'Uninstalling release {release}'

    base_command = ['helm', 'uninstall', release]

    if namespace:
        base_command = base_command + ['--namespace', namespace]
        msg = f'{msg} in namespace {namespace}'

    click.echo(msg)

    try:
        log.debug(f'Uninstall command {base_command}')
        return subprocess.run(base_command, check=True)
    except subprocess.CalledProcessError as e:
        raise ClickException(str(e))


class HelmVersionChecked:
    def __init__(self, req_helm_version: RequiredHelmVersion, local_helm_version: LocalHelmVersion) -> None:
        if local_helm_version < req_helm_version:
            raise ClickException(f'Local helm version {local_helm_version} is lower then required {req_helm_version}')

    def ok(self):
        """
        To prevent variable unused.
        """


@lru_cache(maxsize=None)
def get_helm_version_checked() -> HelmVersionChecked:
    return HelmVersionChecked(
        req_helm_version=required_helm_version,
        local_helm_version=_get_helm_version()
    )


def _get_helm_version() -> LocalHelmVersion:
    command: List[str] = ['helm', 'version', "--template={{.Version}}"]
    try:
        version: str = subprocess.check_output(command, text=True)
        return LocalHelmVersion(version=version)
    except subprocess.CalledProcessError as e:
        raise ClickException(str(e))

def repo_update():
    subprocess.run(['helm', 'repo', 'update'], check=True)

def history(release, output, show_operator, current_operator_version, current_operator_release):
    """Call 'helm history <release>' using subprocess.run"""
    log.debug('Attempting to call: helm history' + f'{release}')
    try:
        if output == 'json':
            result1 = subprocess.run(['helm', 'history', release, '--output', 'json'], check=True, capture_output=True, text=True)
            res1 = json.loads(result1.stdout)
            try:
                result2 = subprocess.run(['helm', 'history', current_operator_release, '--namespace', 'kxi-operator', '--output', 'json'], check=True, capture_output=True, text=True)
                res2 = json.loads(result2.stdout)
            except subprocess.CalledProcessError as e:
                res2 = []
            return res1,res2
        else:
            result1 = subprocess.run(['helm', 'history', release],  stdout=subprocess.PIPE, check=True)
            output1 = result1.stdout.decode('utf-8')
            if not show_operator:
                return print(output1)
            try:
                result2 = subprocess.run(['helm', 'history', current_operator_release, '--namespace', 'kxi-operator'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
                output2 = result2.stdout.decode('utf-8').split('\n')[1:]
            except subprocess.CalledProcessError as e:                
                if current_operator_version == []:
                    output2 = {"Unable to retrieve operator version"}
                else:
                    output2 = {f"Operator is not managed by helm but is currently on version {current_operator_version}"}
            
            res = output1 + '\n' + '\n'.join(output2)
            return print(res)
    except subprocess.CalledProcessError as e:
        click.echo(e)
        return []