from __future__ import annotations

import click
import os
import subprocess
from functools import lru_cache
from typing import List
import json
import pyk8s
import yaml

from click import ClickException
from packaging.version import Version

from kxicli import log
from kxicli.common import parse_called_process_error
from kxicli.commands.common.docker import temp_docker_config
from kxicli.resources import helm_chart

class RequiredHelmVersion(Version):
    pass


class LocalHelmVersion(Version):
    pass


minimum_helm_version: str = '3.8.0'
required_helm_version: RequiredHelmVersion = RequiredHelmVersion(version=minimum_helm_version)


class RepoNotFoundException(Exception):
    pass

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
        existing_values: str = None
) -> subprocess.CompletedProcess:
    """Call 'helm upgrade install' using subprocess.run"""

    base_command = ['helm', 'upgrade', '--install']

    input_arg = None
    text_arg = None
    version_msg = ''

    if version:
        version_msg = ' version ' + version
        base_command = base_command + ['--version', version]

    if values_file:
        click.echo(f'Installing chart {chart}{version_msg} with values file from {values_file}')
        base_command = base_command + ['-f', values_file]
    elif existing_values:
        click.echo(f'Installing chart {chart}{version_msg} with previously used values')
        base_command = base_command + ['-f', '-']
        input_arg = existing_values
        text_arg = True

    base_command = base_command + [release, chart]
    base_command = base_command + args

    if namespace:
        base_command = base_command + ['--namespace', namespace]
        pyk8s.models.V1Namespace.ensure(namespace)

    try:
        log.debug(f'Upgrade install command {base_command}')
        with temp_docker_config(docker_config) as temp_dir:
            helm_env = os.environ.copy()
            helm_env['DOCKER_CONFIG'] = temp_dir
            return subprocess.run(base_command, check=True, input=input_arg, text=text_arg, env=helm_env, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = parse_called_process_error(e)
        raise ClickException(msg)


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

def repo_update(repos: list[str] = None, **kwargs) -> subprocess.CompletedProcess:
    cmd = ['helm', 'repo', 'update']
    if repos is not None:
        cmd += repos
    return subprocess.run(cmd, check=True, **kwargs)

def get_values(release, namespace=None):
    cmd = ['helm', 'get', 'values', release]
    if namespace is not None:
        cmd = cmd + ['--namespace', namespace]

    values = yaml.safe_load(subprocess.run(cmd, check=True, capture_output=True, text=True).stdout)
    values.pop('USER-SUPPLIED VALUES', None)

    return values

def history(release, output, show_operator, current_operator_version, current_operator_release, namespace):
    """Call 'helm history <release>' using subprocess.run"""
    log.debug('Attempting to call: helm history' + f'{release}')
    try:
        if output == 'json':
            result1 = subprocess.run(['helm', 'history', release, '--namespace', namespace, '--output', 'json'], check=True, capture_output=True, text=True)
            res1 = json.loads(result1.stdout)
            try:
                result2 = subprocess.run(['helm', 'history', current_operator_release, '--namespace', 'kxi-operator', '--output', 'json'], check=True, capture_output=True, text=True)
                res2 = json.loads(result2.stdout)
            except subprocess.CalledProcessError as e:
                res2 = []
            return res1,res2
        else:
            result1 = subprocess.run(['helm', 'history', release, '--namespace', namespace],  stdout=subprocess.PIPE, check=True)
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


def repo_exists(chart_repo_name):
    if not any(chart_repo_name == item['name'] for item in repo_list()):
        raise RepoNotFoundException(chart_repo_name)


def add_repo(chart_repo_name, url, username, password):
    """Call 'helm repo add' using subprocess.run"""
    log.debug(
        f'Attempting to call: helm repo add --username {username} --password {len(password)*"*"} {chart_repo_name} {url}')
    try:
        return subprocess.run(['helm', 'repo', 'add', '--username', username, '--password', password, chart_repo_name, url],
                       check=True)
    except subprocess.CalledProcessError:
        # Pass here so that the password isn't printed in the log
        pass


def repo_list():
    """Call 'helm repo list' using subprocess.run"""
    log.debug('Attempting to call: helm repo list')
    try:
        res = subprocess.run(
            ['helm', 'repo', 'list', '--output', 'json'], check=True, capture_output=True, text=True)
        return json.loads(res.stdout)
    except subprocess.CalledProcessError as e:
        click.echo(e)
        return []


def search_repo(
    chart: str,
    args: list[str] = []
) -> subprocess.CompletedProcess:
    cmd = ['helm', 'search', 'repo', chart] + args
    return subprocess.run(cmd, check=True, capture_output=True, text=True)


def list_versions(chart_repo_name):
    """Call 'helm search repo' using subprocess.run"""
    log.debug('Attempting to call: helm search repo')
    try:
        repo_update([chart_repo_name])
        click.echo(f'Listing available kdb Insights Enterprise versions in repo {chart_repo_name}')
        return search_repo(f'{chart_repo_name}/insights')
    except subprocess.CalledProcessError as e:
        raise ClickException(str(e))


def get_operator_versions(
    chart: helm_chart.Chart
) -> list[str]:
    log.debug(f"Searching {chart.repo_name} for versions of kxi-operator")
    extra_args = ['--versions', '--devel', '--output', 'json']
    res = search_repo(f'{chart.repo_name}/kxi-operator', extra_args)
    versions = [x['version'] for x in json.loads(res.stdout)]
    return versions
