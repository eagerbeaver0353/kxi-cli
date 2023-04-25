import base64
import json
import subprocess
import traceback
import urllib
from enum import Enum

import click
import kubernetes as k8s
import yaml
from click import ClickException
from kubernetes import client, utils, dynamic, watch
from kubernetes.client import api_client
from kubernetes.client.rest import ApiException
from kubernetes.utils import FailToCreateError
from urllib3 import HTTPResponse
from urllib3.exceptions import MaxRetryError, HTTPError
from kxicli.options import namespace as options_namespace
from kxicli.commands.common import arg
from kxicli.common import load_kube_config

AZURE_NODENAME_PREFIX: str = 'aks'
GCP_NODENAME_PREFIX: str = 'gke'
AWS_NODENAME_PREFIX: str = 'eks'
K8UP_IMAGE: str = 'ghcr.io/k8up-io/k8up:v2'

K8UP_CRD_URL="https://github.com/k8up-io/k8up/releases/download/k8up-4.0.1/k8up-crd.yaml"

class Provider(Enum):
    @classmethod
    def _missing_(cls, value: str):
        for member in cls:
            if member.value == value.upper():
                return member

    UNKNOWN = 'Unknown - not supported'
    AZURE = 'AZURE'
    GCP = 'GCP'
    AWS = 'AWS'


target_cluster_provider = Provider.UNKNOWN


def _determine_provider():
    load_kube_config()
    api = client.CoreV1Api()
    global target_cluster_provider

    click.secho('Determining cloud provider...', bold=True)
    try:
        node_list = api.list_node()
        for node in node_list.items:
            if AZURE_NODENAME_PREFIX in node.metadata.name:
                target_cluster_provider = Provider.AZURE
                break
            if GCP_NODENAME_PREFIX in node.metadata.name:
                target_cluster_provider = Provider.GCP
                break
            if AWS_NODENAME_PREFIX in node.metadata.name:
                target_cluster_provider = Provider.AWS
                break

        click.secho(
            f'Cloud provider: {target_cluster_provider.value}', bold=True)
        return target_cluster_provider
    except k8s.client.rest.ApiException as exception:
        raise ClickException(
            f'Exception when calling CustomObjectsApi->list_node: {exception}\n')


@click.group()
def backup():
    """Insights data backup related commands"""


@backup.command()
@click.option(
    '--az-stg-acc-name',
    prompt='Please enter Azure storage account name',
    type=click.STRING
)
@click.option(
    '--az-stg-acc-key',
    prompt='Please enter Azure storage account access key',
    type=click.STRING
)
@arg.namespace()
@click.password_option(
    '--restic-pw',
    prompt='Please enter custom Restic repo password'
)
@click.option(
    '--obj-store-provider',
    prompt='Please enter target object store type AZURE/GCP/AWS',
    default=lambda: _determine_provider().value,
    type=click.STRING
)
def init(
        az_stg_acc_name: str,
        az_stg_acc_key: str,
        restic_pw: str,
        obj_store_provider: str,
        namespace: str
):

    click.secho('Init Backup for kdb Insights Enterprise', bold=True)

    _install_operator(namespace)

    _install_crd_definitions(namespace)

    _create_secrets(az_stg_acc_name, az_stg_acc_key, restic_pw, namespace)

    _annotate_postgres(namespace)


@backup.command()
@click.option('--azure-blob-name', prompt='Please enter backup job blob container name')
@arg.namespace()
def snapshots(azure_blob_name, namespace):

    click.secho('Check and list created snapshots', bold=True)
    try:
        _snapshot_pod_creation(azure_blob_name, namespace)

        _snapshot_list_from_logs(namespace)

    finally:
        click.secho('Check and list created snapshots', bold=True)
        _snapshot_pod_deletion(namespace)


@backup.command()
@click.option('--backup-name', prompt='Please enter backup job name')
@arg.namespace()
@click.option('--azure-blob-name', prompt='Please enter backup job blob container name')
def set_backup(backup_name, azure_blob_name, namespace):

    click.secho('Configure and start a backup', bold=True)

    _create_backup(backup_name, azure_blob_name, namespace)


def _create_backup(backup_name, azure_blob_name, namespace):
    api = dynamic.DynamicClient(
        api_client.ApiClient(configuration=load_kube_config())
    )

    crd_api = api.resources.get(
        api_version="k8up.io/v1", kind="Backup"
    )

    azure_crd_manifest = {
        "apiVersion": "k8up.io/v1",
        "kind": "Backup",
        "metadata": {
            "name": backup_name,
            "namespace": namespace,
        },
        "spec": {
            "failedJobsHistoryLimit": 2,
            "successfulJobsHistoryLimit": 2,
            "backend": {
                "repoPasswordSecretRef": {
                    "name": "backup-repo",
                    "key": "password"
                },
                "azure": {
                    "container": azure_blob_name,
                    "accountNameSecretRef": {
                        "name": "azure-blob-creds",
                        "key": "username"
                    },
                    "accountKeySecretRef": {
                        "name": "azure-blob-creds",
                        "key": "password"
                    }
                }
            },
        },
    }
    try:
        crd_creation_response = crd_api.create(azure_crd_manifest)
        click.echo(
            f'K8up Backup CRD creation done: {crd_creation_response.metadata.name}')
    except Exception as e:
        raise ClickException(f'CRD creation failed: {e}\n')


def _snapshot_pod_creation(azure_blob_name, namespace):
    api = dynamic.DynamicClient(
        api_client.ApiClient(configuration=load_kube_config())
    )

    crd_api = api.resources.get(
        api_version="v1", kind="Pod"
    )

    k8up_snapshot_list_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
                "name": "k8up-snapshot-list-pod",
                "namespace": namespace,
                "labels": {
                    "name": "k8up-snapshot-list-pod"
                },
        },
        "spec": {
            "containers": [
                {
                    "name": "k8up-snapshot-list",
                    "command": [
                            "/usr/local/bin/restic",
                            "snapshots"
                    ],
                    "env": [
                        {
                            "name": "AZURE_ACCOUNT_KEY",
                            "valueFrom": {
                                "secretKeyRef": {
                                    "key": "password",
                                    "name": "azure-blob-creds"
                                }
                            }
                        },
                        {
                            "name": "AZURE_ACCOUNT_NAME",
                            "valueFrom": {
                                "secretKeyRef": {
                                    "key": "username",
                                    "name": "azure-blob-creds"
                                }
                            }
                        },
                        {
                            "name": "RESTIC_REPOSITORY",
                            "value": "azure:"+azure_blob_name+":/"
                        },
                        {
                            "name": "STATS_URL"
                        },
                        {
                            "name": "AWS_ACCESS_KEY_ID"
                        },
                        {
                            "name": "HOSTNAME",
                            "value": "insights"
                        },
                        {
                            "name": "AWS_SECRET_ACCESS_KEY"
                        },
                        {
                            "name": "RESTIC_PASSWORD",
                            "valueFrom": {
                                "secretKeyRef": {
                                    "key": "password",
                                    "name": "backup-repo"
                                }
                            }
                        }
                    ],
                    "image": K8UP_IMAGE,
                    "imagePullPolicy": "IfNotPresent",
                    "resources": {}
                }
            ],
            "restartPolicy": "Never"
        }
    }
    try:
        job_creation_response = crd_api.create(k8up_snapshot_list_manifest)
        click.echo(
            f'Pod creation done: {job_creation_response.metadata.name}\n')
    except Exception as e:
        raise ClickException(f'Pod creation failed: {e}\n')


def _snapshot_list_from_logs(namespace):
    load_kube_config()
    w = watch.Watch()
    pod_name = "k8up-snapshot-list-pod"
    api_instance = client.CoreV1Api()
    try:
       for event in w.stream(func=api_instance.list_namespaced_pod,
                              namespace=namespace,
                              label_selector="name=k8up-snapshot-list-pod",
                              timeout_seconds=60):
            if event["object"].status.phase == "Succeeded":
                w.stop()
                api_response = api_instance.read_namespaced_pod_log(
                    name=pod_name, namespace=namespace)
                click.echo(api_response)
                return
    except ApiException as e:
        raise ClickException(
            f'Found exception in reading the logs, timed out: {str(e)}')


def _annotate_postgres(namespace):
    load_kube_config()
    pod_name = "insights-postgresql-0"
    body = {
        "metadata":{
            "annotations": {
                "k8up.io/backupcommand": 'sh -c \'PGDATABASE="$POSTGRES_DB" PGUSER="$POSTGRES_USER" PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --clean\'',
                "k8up.io/file-extension": '.sql'
                }
            }
    }
    try:
        api_instance = client.CoreV1Api()
        api_response = api_instance.patch_namespaced_pod(
            name=pod_name, namespace=namespace, body=body
            )
        click.echo(f'Postgres pod annotation successful: {api_response.pod_name}')
    except ApiException as e:
        raise ClickException(
            f'Found exception in Postgres pod annotation: {str(e)}')
    

def _snapshot_pod_deletion(namespace):
    load_kube_config()
    pod_name = "k8up-snapshot-list-pod"
    try:
        api_instance = client.CoreV1Api()
        api_instance.delete_namespaced_pod(
            name=pod_name, namespace=namespace)
        click.echo(f'Pod deletion successful: {pod_name}')
    except ApiException as e:
        raise ClickException(
            f'Found exception in deleting pod: {pod_name}, {str(e)}')


def _create_secrets(az_stg_acc_name, az_stg_acc_key, restic_pw, namespace):
    data = {'username': base64.b64encode(az_stg_acc_name.encode()).decode(
    ), 'password': base64.b64encode(az_stg_acc_key.encode()).decode()}
    load_kube_config()
    core_api_instance = client.CoreV1Api()
    pretty = 'true'
    body = client.V1Secret()
    body.api_version = 'v1'
    body.data = data
    body.kind = 'Secret'
    body.metadata = {'name': 'azure-blob-creds'}
    body.type = 'Opaque'
    try:
        core_api_instance.create_namespaced_secret(
            namespace, body, pretty=pretty)
        click.echo(f'Secret created: azure-blob-creds')
    except ApiException as e:
        traceback.print_exc()
        raise ClickException("%s" % (str(e)))

    data = {'password': base64.b64encode(restic_pw.encode()).decode()}
    body.data = data
    body.metadata = {'name': 'backup-repo'}
    try:
        core_api_instance.create_namespaced_secret(
            namespace, body, pretty=pretty)
        click.echo(f'Secret created: backup-repo')
    except ApiException as e:
        traceback.print_exc()
        raise ClickException("%s" % (str(e)))


def _install_operator(namespace):
    try:
        subprocess.run(['helm', 'repo', 'add', 'k8up-io',
                       'https://k8up-io.github.io/k8up'], check=True)
    except subprocess.CalledProcessError as cpe:
        raise ClickException(str(cpe))

    install_base_command = ['helm', 'upgrade', '--install',
                            '--namespace', namespace, 'k8up', 'k8up-io/k8up']
    try:
        subprocess.run(install_base_command, check=True)
        click.secho('Kubernetes Backup Operator installed.', bold=True)
    except subprocess.CalledProcessError as cpe:
        raise ClickException(str(cpe))


def _install_crd_definitions(namespace):
    load_kube_config()
    k8s_client = client.ApiClient()
    yamlcontent = yaml.safe_load_all(urllib.request.urlopen(K8UP_CRD_URL))
    for y in yamlcontent:
        try:
            utils.create_from_dict(k8s_client, y, namespace=namespace)
            click.secho(
                'Kubernetes Backup Operator CRD definitions created.', bold=True)
        except (ApiException, FailToCreateError, HTTPError) as e:
            raise ClickException(f'CRD definition creation failed: {str(e)}\n')
