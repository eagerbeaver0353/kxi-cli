import time
import random
import sys
import json
import yaml
import click
import kubernetes as k8s
from kxicli import common
from kxicli import log

API_GROUP = 'insights.kx.com'
API_VERSION = 'v1'
API_PLURAL = 'assemblies'

@click.group()
def assembly():
    """Assembly interaction commands"""

def _format_assembly_status(assembly):
    """Format Kubernetes assembly status into CLI assembly status"""
    status = {}
    if 'status' in assembly and 'conditions' in assembly['status']:
        for d in assembly['status']['conditions']:
            cdata = { 'status': d['status'] }
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


def _list_assemblies(namespace):
    """List assemblies"""
    common.load_kube_config()
    api = k8s.client.CustomObjectsApi()
    res = api.list_namespaced_custom_object(
        group=API_GROUP,
        version=API_VERSION,
        namespace=namespace,
        plural=API_PLURAL,
        )

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
        padding =len(max(first_col, key=len)) + 2

    click.echo(f'{headers[0]:{padding}}{headers[1]}')
    for row in data:
        click.echo(f'{row[0]:{padding}}{row[1]}')

@assembly.command()
@click.option('--namespace', default=lambda: common.get_default_val('namespace'), help='Namespace to create assembly in')
@click.option('--filepath', required=True, help='Path to assembly file')
@click.option('--wait', is_flag=True, help='Wait for all pods to be running')
def create(namespace, filepath, wait):
    """Create an assembly given an assembly file"""
    common.load_kube_config()
    api = k8s.client.CustomObjectsApi()

    with open(filepath) as f:
        try:
            body = yaml.safe_load(f)
        except yaml.YAMLError as e:
            log.error(f'Invalid assembly file {filepath}')
            click.echo(e)
            sys.exit(1)

    click.echo(f'Submitting assembly from {filepath}')

    api_version = body['apiVersion'].split('/')

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
                    sys.exit(0)

    click.echo(f'Custom assembly resource {body["metadata"]["name"]} created!')

@assembly.command()
@click.option('--namespace', default=lambda: common.get_default_val('namespace'), help='Namespace that the assembly is in')
@click.option('--name', required=True, help='Name of the assembly get the status of')
@click.option('--wait-for-ready', is_flag=True, help='Wait for assembly to reach "Ready" state')
def status(namespace, name, wait_for_ready):
    """Print status of the assembly"""
    if wait_for_ready:
        with click.progressbar(range(10), label='Waiting for assembly to enter "Ready" state') as bar:
            for n in bar:
                time.sleep((2 ** n) + (random.randint(0, 1000) / 1000))
                if _assembly_status(namespace, name, print_status=True):
                    sys.exit(0)
    else:
        _assembly_status(namespace, name, print_status=True)

@assembly.command()
@click.option('--namespace', default=lambda: common.get_default_val('namespace'), help='Namespace that the assemblies are in')
def list(namespace):
    """List assemblies"""
    if _list_assemblies(namespace):
        sys.exit(0)
    else:
        sys.exit(1)

@assembly.command()
@click.option('--namespace', default=lambda: common.get_default_val('namespace'), help='Namespace that the assembly is in')
@click.option('--name', required=True, help='Name of the assembly to delete')
@click.option('--wait', is_flag=True, help='Wait for all pods to be deleted')
@click.option('--force', is_flag=True, help='Delete assembly without getting confirmation')
def delete(namespace, name, wait, force):
    """Deletes an assembly given its name"""
    click.echo(f'Deleting assembly {name}')

    if not force and not click.confirm(f'Are you sure you want to delete {name}'):
        click.echo(f'Not deleting assembly {name}')
        sys.exit(0)

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
            click.echo(f'Ignoring delete, {name} not found')
            sys.exit(0)
        else:
            click.echo(f'Exception when calling CustomObjectsApi->delete_namespaced_custom_object: {exception}\n')

    if wait:
        with click.progressbar(range(10), label='Waiting for assembly to be deleted') as bar:
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
                        sys.exit(0)

        log.error('Assembly was not deleted in time, exiting')
        sys.exit(1)

def get_preferred_api_version(group_name):
    k8s.config.load_config()
    api_instance = k8s.client.ApisApi()

    version = None
    for api in api_instance.get_api_versions().groups:
        if  api.name == group_name:
            version = api.preferred_version.version

    if version == None:
        log.error(f'Could not find preferred API version for group {group_name}')
        sys.exit(1)

    return version
