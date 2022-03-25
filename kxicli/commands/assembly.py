import time
import random
import sys
import yaml
import click
import kubernetes as k8s
from kxicli import common
from kxicli import log

@click.group()
def assembly():
    """Assembly interaction commands"""

def _assembly_status(namespace, name, print_status=False):
    """Get status of assembly"""
    common.load_kube_config()
    v1 = k8s.client.CoreV1Api()
    res = v1.list_namespaced_pod(namespace, label_selector=f'insights.kx.com/app={name}')

    is_running = [ pod.status.phase == 'Running' for pod in res.items ]

    stat_list = []
    if print_status:
        for pod in res.items:
            stat_list.append((pod.metadata.name, pod.status.phase))
            
        _print_2d_list(stat_list, ['POD', 'STATUS'])

    if all(is_running):
        return True
    else:
        return False

def _list_assemblies(namespace):
    """List assemblies"""
    common.load_kube_config()
    v1 = k8s.client.CustomObjectsApi()
    res = v1.list_namespaced_custom_object(group="insights.kx.com", version="v1", namespace=namespace, plural="assemblies")
    
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

    click.echo(f'Custom assembly resource {body["metadata"]["name"]} created!')

    if wait:
        with click.progressbar(range(10), label='Waiting for all pods to be running') as bar:
            for n in bar:
                time.sleep((2 ** n) + (random.randint(0, 1000) / 1000))
                if _assembly_status(namespace, body['metadata']['name']):
                    sys.exit(0)

@assembly.command()
@click.option('--namespace', default=lambda: common.get_default_val('namespace'), help='Namespace that the assembly is in')
@click.option('--name', required=True, help='Name of the assembly get the status of')
def status(namespace, name):
    """Print status of the assembly"""
    if _assembly_status(namespace, name, print_status=True):
        sys.exit(0)
    else:
        sys.exit(1)
        
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

    if not force:
        if click.confirm(f'Are you sure you want to delete {name}'):
            pass
        else:
            click.echo(f'Not deleting assembly {name}')
            sys.exit(0)

    common.load_kube_config()
    api = k8s.client.CustomObjectsApi()

    try:
        api.delete_namespaced_custom_object(
            group='insights.kx.com',
            version=get_preferred_api_version('insights.kx.com'),
            namespace=namespace,
            plural='assemblies',
            name=name,
            )
    except k8s.client.rest.ApiException as exception:
        if exception.status == 404:
            click.echo(f'Ignoring delete, {name} not found')
            sys.exit(0)
        else:
            click.echo(f'Exception when calling CustomObjectsApi->delete_namespaced_custom_object: {exception}\n')

    if wait:
        v1 = k8s.client.CoreV1Api()
        with click.progressbar(range(10), label='Waiting for all pods to be deleted') as bar:
            for n in bar:
                time.sleep((2 ** n) + (random.randint(0, 1000) / 1000))
                res = v1.list_namespaced_pod(namespace, label_selector=f'insights.kx.com/app={name}')
                if [] == res.items:
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
