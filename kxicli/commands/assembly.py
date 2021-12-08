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

    if print_status:
        click.echo('POD\tSTATUS')
        for pod in res.items:
            click.echo(f'{pod.metadata.name}: {pod.status.phase}')

    if all(is_running):
        return True
    else:
        return False

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

    api.create_namespaced_custom_object(
        group='insights.kx.com',
        version='v1alpha1',
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
            version='v1alpha1',
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
