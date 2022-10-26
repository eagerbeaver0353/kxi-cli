import copy
import json
import os
import random
import sys
import time
from tempfile import mkstemp
from functools import partial

import click
import kubernetes as k8s
import yaml

from kxicli import common
from kxicli import log
from kxicli.commands.common.arg import arg_assembly_backup_filepath, arg_assembly_filepath, \
     arg_assembly_name, arg_assembly_wait, arg_force, arg_namespace
from kxicli.common import get_default_val as default_val
from kxicli.common import get_help_text as help_text
from kxicli.options import namespace as options_namespace, assembly_backup_filepath, assembly_filepath

API_GROUP = 'insights.kx.com'
API_VERSION = 'v1'
API_PLURAL = 'assemblies'
CONFIG_ANNOTATION = 'kubectl.kubernetes.io/last-applied-configuration'
ASM_LABEL_SELECTOR = 'insights.kx.com/queryEnvironment!=true'

arg_assembly_backup_filepath = assembly_backup_filepath.decorator(click_option_args=['--filepath'])


@click.group()
def assembly():
    """Assembly interaction commands"""


def _format_assembly_status(assembly):
    """Format Kubernetes assembly status into CLI assembly status"""
    status = {}
    if 'status' in assembly and 'conditions' in assembly['status']:
        for d in assembly['status']['conditions']:
            cdata = {'status': d['status']}
            if 'message' in d:
                cdata['message'] = d['message']
            if 'reason' in d:
                cdata['reason'] = d['reason']

            status[d['type']] = cdata

    return status


def _assembly_status(namespace, name, print_status=False):
    """Get status of assembly"""
    common.load_kube_config()
    api = k8s.client.CustomObjectsApi()

    try:
        res = api.get_namespaced_custom_object(
            group=API_GROUP,
            version=API_VERSION,
            namespace=namespace,
            plural=API_PLURAL,
            name=name,
        )
    except k8s.client.rest.ApiException as exception:
        if exception.status == 404:
            click.echo(f'Assembly {name} not found')
            sys.exit(1)
        else:
            click.echo(f'Exception when calling CustomObjectsApi->get_namespaced_custom_object: {exception}\n')

    assembly_status = _format_assembly_status(res)

    if print_status:
        if len(assembly_status) == 0:
            click.echo('Assembly not yet deployed')
            sys.exit(1)
        else:
            click.echo(json.dumps(assembly_status, indent=2))

    if 'AssemblyReady' not in assembly_status:
        click.echo('Could not find the "AssemblyReady" condition in the Assembly Status')
        return False

    return assembly_status['AssemblyReady']['status'] == 'True'


def _get_assemblies_list(namespace, label_selector=ASM_LABEL_SELECTOR):
    """List assemblies"""
    common.load_kube_config()
    api = k8s.client.CustomObjectsApi()
    res = api.list_namespaced_custom_object(
        group=API_GROUP,
        version=API_VERSION,
        namespace=namespace,
        plural=API_PLURAL,
        label_selector=label_selector,
    )
    return res


def _list_assemblies(namespace):
    """List assemblies"""
    res = _get_assemblies_list(namespace)

    asm_list = []
    if 'items' in res:
        for asm in res['items']:
            if 'metadata' in asm and 'name' in asm['metadata']:
                asm_list.append((asm['metadata']['name'], asm['metadata']['namespace']))

    _print_2d_list(asm_list, ['ASSEMBLY NAME', 'NAMESPACE'])

    return True


def _print_2d_list(data, headers):
    """
    Prints a col-formatted 2d list
    """
    first_col = [row[0] for row in data]
    padding = len(max(headers, key=len)) + 2
    if len(data) != 0:
        padding = max(padding, len(max(first_col, key=len)) + 2)

    click.echo(f'{headers[0]:{padding}}{headers[1]}')
    for row in data:
        click.echo(f'{row[0]:{padding}}{row[1]}')


def _backup_assemblies(namespace, filepath, force):
    """Get assemblies' definitions"""
    res = _get_assemblies_list(namespace)
    backup = copy.deepcopy(res)
    backup['items'] = []

    asm_list = []
    asm_backup_list = []

    if 'items' in res:
        for asm in res['items']:
            if 'metadata' in asm and 'name' in asm['metadata']:
                asm_list.append(asm['metadata']['name'])
                if 'annotations' in asm['metadata'] and CONFIG_ANNOTATION in asm['metadata']['annotations']:
                    asm_backup_list.append(asm['metadata']['name'])
                    last_applied = json.loads(asm['metadata']['annotations'][CONFIG_ANNOTATION])
                    backup['items'].append(last_applied)

    if len(asm_list) == 0:
        click.echo('No assemblies to back up')
        return None

    asm_exclude_list = [x for x in asm_list if x not in asm_backup_list]

    filepath = _backup_filepath(filepath, force)

    with open(filepath, 'w') as f:
        yaml.dump(backup, f)

    if len(asm_exclude_list) > 0:
        log.warn(f"Refusing to backup assemblies: {asm_exclude_list}. These assemblies are missing 'kubectl.kubernetes.io/last-applied-configuration' annotation. Please restart these assemblies manually.")

    click.echo(f'Persisted assembly definitions for {asm_backup_list} to {filepath}')

    return filepath


def _backup_filepath(filepath, force):
    if filepath: 
        if not force and os.path.exists(filepath) and \
            not click.confirm(f'\n{filepath} file exists. Do you want to overwrite it with a new assembly backup file?'):
            filepath = click.prompt('Please enter the path to write the assembly backup file')
    else:
        _, filepath = mkstemp(f'-{common.DEFAULT_VALUES[common.key_assembly_backup_file]}')

    return filepath


def _read_assembly_file(filepath):
    if not os.path.exists(filepath):
        log.error(f'File not found: {filepath}')
        sys.exit(1)

    with open(filepath) as f:
        try:
            body = yaml.safe_load(f)
        except yaml.YAMLError as e:
            log.error(f'Invalid assembly file {filepath}')
            click.echo(e)
            sys.exit(1)

    return body


def _create_assemblies_from_file(namespace, filepath, wait=None):
    """Apply assemblies from file"""
    if not filepath:
        click.echo('No assemblies to restore')
        return None

    asm_list = _read_assembly_file(filepath)

    click.echo(f'Submitting assembly from {filepath}')
    created = []

    if 'items' in asm_list:
        for asm in asm_list['items']:
            click.echo(f"Submitting assembly {asm['metadata']['name']}")
            try:
                created.append(_create_assembly(namespace, asm, wait))
            except BaseException as e:
                click.echo(f"Error applying assembly {asm['metadata']['name']}: {e}")
    else:
        created.append(_create_assembly(namespace, asm_list, wait))

    return created

def _add_last_applied_configuration_annotation(body):
    annotated_body = copy.deepcopy(body)

    # ensure annotations exist
    if 'annotations' not in annotated_body['metadata']:
        annotated_body['metadata']['annotations'] = {}

    annotated_body['metadata']['annotations'][CONFIG_ANNOTATION] = "\n" + json.dumps(annotated_body)

    return annotated_body


def _create_assembly(namespace, body, wait=None):
    """Create an assembly"""
    common.load_kube_config()
    api = k8s.client.CustomObjectsApi()

    if 'resourceVersion' in body['metadata']:
        del body['metadata']['resourceVersion']
    api_version = body['apiVersion'].split('/')
    body = _add_last_applied_configuration_annotation(body)

    api.create_namespaced_custom_object(
        group=api_version[0],
        version=api_version[1],
        namespace=namespace,
        plural='assemblies',
        body=body,
    )

    if wait:
        with click.progressbar(range(10), label='Waiting for assembly to enter "Ready" state') as bar:
            for n in bar:
                time.sleep((2 ** n) + (random.randint(0, 1000) / 1000))
                if _assembly_status(namespace, body['metadata']['name']):
                    break

    click.echo(f'Custom assembly resource {body["metadata"]["name"]} created!')
    return True


def _delete_assembly(namespace, name, wait, force):
    """Deletes an assembly given its name"""
    click.echo(f'Tearing down assembly {name}')

    if not force and not click.confirm(f'Are you sure you want to teardown {name}'):
        click.echo(f'Not tearing down assembly {name}')
        return False

    common.load_kube_config()
    api = k8s.client.CustomObjectsApi()

    try:
        api.delete_namespaced_custom_object(
            group=API_GROUP,
            version=get_preferred_api_version(API_GROUP),
            namespace=namespace,
            plural=API_PLURAL,
            name=name,
        )
    except k8s.client.rest.ApiException as exception:
        if exception.status == 404:
            click.echo(f'Ignoring teardown, {name} not found')
            return False
        else:
            click.echo(f'Exception when calling CustomObjectsApi->delete_namespaced_custom_object: {exception}\n')

    asm_running = True
    if wait:
        with click.progressbar(range(10), label='Waiting for assembly to be torn down') as bar:
            for n in bar:
                time.sleep((2 ** n) + (random.randint(0, 1000) / 1000))
                try:
                    api.get_namespaced_custom_object(
                        group=API_GROUP,
                        version=API_VERSION,
                        namespace=namespace,
                        plural=API_PLURAL,
                        name=name,
                    )
                except k8s.client.rest.ApiException as exception:
                    if exception.status == 404:
                        asm_running = False
                        break

        if asm_running:
            log.error('Assembly was not torn down in time, exiting')
            return False

    return True


def _delete_running_assemblies(namespace, wait, force):
    """Deletes all assemblies running in a namespace"""
    asm_list = _get_assemblies_list(namespace)
    deleted = []
    if 'items' in asm_list:
        for asm in asm_list['items']:
            if 'metadata' in asm and 'name' in asm['metadata']:
                deleted.append(
                    _delete_assembly(namespace=namespace, name=asm['metadata']['name'], wait=wait, force=force))

    return deleted


@assembly.command()
@arg_namespace()
@arg_assembly_backup_filepath()
@arg_force()
def backup(namespace, filepath, force):
    """Back up running assemblies to a file"""

    namespace = options_namespace.prompt(namespace)

    _backup_assemblies(namespace, filepath, force)


@assembly.command()
@arg_namespace()
@arg_assembly_filepath()
@arg_assembly_wait()
def create(namespace, filepath, wait):
    """Create an assembly given an assembly file"""

    namespace = options_namespace.prompt(namespace)
    filepath = assembly_filepath.prompt(filepath)

    _create_assemblies_from_file(namespace, filepath, wait)


@assembly.command()
@arg_namespace()
@arg_assembly_name()
@arg_assembly_wait()
def status(namespace, name, wait):
    """Print status of the assembly"""

    namespace = options_namespace.prompt(namespace)

    if wait:
        with click.progressbar(range(10), label='Waiting for assembly to enter "Ready" state') as bar:
            for n in bar:
                time.sleep((2 ** n) + (random.randint(0, 1000) / 1000))
                if _assembly_status(namespace, name, print_status=True):
                    sys.exit(0)
    else:
        _assembly_status(namespace, name, print_status=True)


@assembly.command()
@arg_namespace()
def list(namespace):
    """List assemblies"""

    namespace = options_namespace.prompt(namespace)

    if _list_assemblies(namespace):
        sys.exit(0)
    else:
        sys.exit(1)


@assembly.command()
@arg_namespace()
@arg_assembly_name()
@arg_assembly_wait()
@arg_force()
def teardown(namespace, name, wait, force):
    """Tears down an assembly given its name"""

    namespace = options_namespace.prompt(namespace)

    _delete_assembly(namespace, name, wait, force)


@assembly.command()
@arg_namespace()
@arg_assembly_name()
@arg_assembly_wait()
@arg_force()
def delete(namespace, name, wait, force):
    """Deletes an assembly given its name"""

    namespace = options_namespace.prompt(namespace)

    _delete_assembly(namespace, name, wait, force)


def get_preferred_api_version(group_name):
    k8s.config.load_config()
    api_instance = k8s.client.ApisApi()

    version = None
    for api in api_instance.get_api_versions().groups:
        if api.name == group_name:
            version = api.preferred_version.version

    if version == None:
        log.error(f'Could not find preferred API version for group {group_name}')
        sys.exit(1)

    return version
