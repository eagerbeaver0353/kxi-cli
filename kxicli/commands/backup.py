import base64
import json
import subprocess
import traceback
import urllib
from enum import Enum

import click
import pyk8s
import yaml
from click import ClickException
from urllib3 import HTTPResponse
from urllib3.exceptions import MaxRetryError, HTTPError
from kxicli.options import namespace as options_namespace
from kxicli.commands.common import arg
from kxicli.cli_group import ProfileAwareGroup, cli

AZURE_NODENAME_PREFIX: str = 'aks'
GCP_NODENAME_PREFIX: str = 'gke'
AWS_NODENAME_PREFIX: str = 'eks'
K8UP_IMAGE: str = 'ghcr.io/k8up-io/k8up:v2'

K8UP_CRD_URL="https://github.com/k8up-io/k8up/releases/download/k8up-4.3.0/k8up-crd.yaml"
K8UP_HELM_VERSION="4.3.0"

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
    global target_cluster_provider

    click.secho('Determining cloud provider...', bold=True)
    try:
        node_list = pyk8s.cl.nodes.get()
        for node in node_list:
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
    except Exception as exception:
        raise ClickException(
            f'Exception when trying to list Kubernetes Nodes: {exception}\n')


@cli.group(cls=ProfileAwareGroup)
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
        pod=_snapshot_pod_creation(azure_blob_name, namespace)

        _snapshot_list_from_logs(pod)

    finally:
        click.secho('Deleting pod', bold=True)
        _snapshot_pod_deletion(namespace)


@backup.command()
@click.option('--backup-name', prompt='Please enter backup job name')
@arg.namespace()
@click.option('--azure-blob-name', prompt='Please enter backup job blob container name')
def set_backup(backup_name, azure_blob_name, namespace):

    click.secho('Configure and start a backup', bold=True)

    _create_backup(backup_name, azure_blob_name, namespace)


def _create_backup(backup_name, azure_blob_name, namespace):
    crd_api = pyk8s.cl.get_api(kind="Backup")

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
        job_creation_response = pyk8s.cl.pods.create(k8up_snapshot_list_manifest)
        click.echo(
            f'Pod creation done: {job_creation_response.metadata.name}\n')
        return job_creation_response
    except Exception as e:
        raise ClickException(f'Pod creation failed: {e}\n')


def _snapshot_list_from_logs(pod):
    click.echo('Reading logs')
    pod.wait_until_status("Succeeded", timeout=60)
    click.echo("\n".join(pod.logs()))


def _annotate_postgres(namespace):
    pod = pyk8s.cl.pods.read("insights-postgresql-0", namespace=namespace)
    try:
        pod.metadata.annotations.update({
                "k8up.io/backupcommand": 'sh -c \'PGDATABASE="$POSTGRES_DB" PGUSER="$POSTGRES_USER" PGPASSWORD="$POSTGRES_PASSWORD" pg_dump --clean\'',
                "k8up.io/file-extension": '.sql'
        })
        pod.patch_()
        click.echo(f'Postgres pod annotation successful: {pod.metadata.name}')
    except Exception as e:
        raise ClickException(
            f'Found exception in Postgres pod annotation: {str(e)}')


def _snapshot_pod_deletion(namespace):
    pod = pyk8s.cl.pods.read("k8up-snapshot-list-pod", namespace=namespace)
    try:
        pod.delete_()
        click.echo(f'Pod deletion successful: {pod.metadata.name}')
    except Exception as e:
        raise ClickException(
            f'Found exception in deleting pod: {pod.metadata.name}, {str(e)}')


def _create_secrets(az_stg_acc_name, az_stg_acc_key, restic_pw, namespace):
    secret = pyk8s.models.V1Secret()
    secret.metadata.name = 'azure-blob-creds'
    secret.set("username", az_stg_acc_name)
    secret.set("password", az_stg_acc_key)

    try:
        secret.create_(namespace=namespace)
        click.echo(f'Secret created: {secret.metadata.name}')
    except Exception as e:
        traceback.print_exc()
        raise ClickException("%s" % (str(e)))

    secret.set("password", restic_pw)
    secret.metadata.name = 'backup-repo'
    try:
        secret.create_(namespace=namespace)
        click.echo(f'Secret created: {secret.metadata.name}')
    except Exception as e:
        traceback.print_exc()
        raise ClickException("%s" % (str(e)))


def _install_operator(namespace):
    try:
        subprocess.run(['helm', 'repo', 'add', 'k8up-io',
                       'https://k8up-io.github.io/k8up'], check=True)
    except subprocess.CalledProcessError as cpe:
        raise ClickException(str(cpe))

    install_base_command = ['helm', 'upgrade', '--install',
                            '--namespace', namespace, 'k8up', 'k8up-io/k8up', '--version', K8UP_HELM_VERSION]
    try:
        subprocess.run(install_base_command, check=True)
        click.secho('Kubernetes Backup Operator installed.', bold=True)
    except subprocess.CalledProcessError as cpe:
        raise ClickException(str(cpe))


def _install_crd_definitions(namespace):
    yamlcontent = yaml.safe_load_all(urllib.request.urlopen(K8UP_CRD_URL))
    for y in yamlcontent:
        try:
            pyk8s.cl.apply(data=y, namespace=namespace)
            click.secho(
                'Kubernetes Backup Operator CRD definitions created.', bold=True)
        except (pyk8s.exceptions.ApiException, HTTPError) as e:
            raise ClickException(f'CRD definition creation failed: {str(e)}\n')
