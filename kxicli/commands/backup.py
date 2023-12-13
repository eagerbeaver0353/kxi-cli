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


def _define_storage_details(obj_store_provider, stg_endpoint, stg_acc_name, stg_acc_key, stg_container_name):

    click.secho('Defining storage details...', bold=True)

    storage_details = {}
    
    if obj_store_provider == 'AZURE':
        storage_details['provider'] = obj_store_provider.lower()
        storage_details['username'] = stg_acc_name  
        storage_details['password'] = stg_acc_key
        storage_details['container'] = stg_container_name

    elif obj_store_provider == 'AWS':
        storage_details['provider'] = 's3'
        storage_details['endpoint'] = stg_endpoint
        storage_details['username'] = stg_acc_name  
        storage_details['password'] = stg_acc_key
        storage_details['bucket'] = stg_container_name

    else:
        click.secho('Error storage provider %s not supported.' % obj_store_provider)
        sys.exit(1)

    click.secho('Storage details defined[%s]' % storage_details)

    return storage_details


@cli.group(cls=ProfileAwareGroup)
def backup():
    """Insights data backup related commands"""


@backup.command()
@click.option(
    '--stg-acc-name',
    prompt='Please enter Azure storage account or AWS access key ID',
    type=click.STRING
)
@click.option(
    '--stg-acc-key',
    prompt='Please enter Azure storage account key or AWS S3 secret access key',
    type=click.STRING
)
@click.option(
    '--stg-container-name',
    prompt='Please enter Azure container or AWS bucket name',
    default='insights-backup',
    type=click.STRING
)
@click.option(
    '--stg-endpoint',
    prompt='Please enter AWS storage endpoint URL (if applicable)',
    default='N/A',
    type=click.STRING
)
@click.option(
    '--obj-store-provider',
    prompt='Please enter target object store type AZURE/GCP/AWS',
    default=lambda: _determine_provider().value,
    type=click.STRING
)
@arg.namespace()
@click.password_option(
    '--restic-pw',
    prompt='Please enter custom Restic repo password'
)

def init(
        namespace: str,
        stg_acc_name: str,
        stg_acc_key: str,
        stg_container_name: str,
        stg_endpoint: str,
        obj_store_provider: str,
        restic_pw: str,
):

    click.secho('Init Backup for kdb Insights Enterprise', bold=True)
    _install_operator(namespace)

    _install_crd_definitions(namespace)

    storage_details = _define_storage_details(obj_store_provider, stg_endpoint, \
        stg_acc_name, stg_acc_key, stg_container_name)

    _create_secrets(storage_details, restic_pw, namespace)

    _annotate_postgres(namespace)


@backup.command()
@click.option('--backup-name', prompt='Please enter backup job name')
@arg.namespace()
def snapshots(backup_name, namespace):

    click.secho('Check and list created snapshots', bold=True)
    try:
        pod=_snapshot_pod_creation(backup_name, namespace)

        _snapshot_list_from_logs(pod)

    finally:
        click.secho('Deleting pod', bold=True)
        _snapshot_pod_deletion(namespace)


@backup.command()
@click.option('--backup-name', prompt='Please enter backup job name')
@arg.namespace()
def set_backup(backup_name, namespace):

    click.secho('Configure and start a backup', bold=True)

    _annotate_rwo_pvcs(namespace)

    _create_backup(backup_name, namespace)


def _create_backup(backup_name, namespace):
    crd_api = pyk8s.cl.get_api(kind="Backup")

    crd_manifest = {
        "apiVersion": "k8up.io/v1",
        "kind": "Backup",
        "metadata": {
            "name": backup_name,
            "namespace": namespace,
        },
        "spec" : {
            "tags": [ backup_name ],
            "failedJobsHistoryLimit": 2,
            "successfulJobsHistoryLimit": 2,
            "backend": {
                "repoPasswordSecretRef": {
                    "name": "backup-repo",
                    "key": "password"
                }
            }
        }
    }

    credential_store = pyk8s.cl.secrets.get(name='backup-storage-creds', namespace=namespace)['data']
    provider = base64.b64decode(credential_store["provider"]).decode()

    if provider == 'azure':

        crd_manifest["spec"]["backend"][provider] = {
            "container": base64.b64decode(credential_store["container"]).decode(),
            "accountNameSecretRef": {
                "name": "backup-storage-creds",
                "key": "username"
            },
            "accountKeySecretRef": {
                "name": "backup-storage-creds",
                "key": "password"
            }
        }

    elif provider == "s3":

        crd_manifest["spec"]["backend"][provider] = {
            "endpoint": base64.b64decode(credential_store["endpoint"]).decode('utf-8'),
            "bucket": base64.b64decode(credential_store["bucket"]).decode(),
            "accessKeyIDSecretRef": {
                "name": "backup-storage-creds",
                "key": "username"
            },
            "secretAccessKeySecretRef": {
                "name": "backup-storage-creds",
                "key": "password"
            }
        }

    else:
        click.secho("Prvider not supported")
        sys.exit(1)

    try:
        crd_creation_response = crd_api.create(crd_manifest)
        click.echo(
            f'K8up Backup CRD creation done: {crd_creation_response.metadata.name}')
    except Exception as e:
        raise ClickException(f'CRD creation failed: {e}\n')
    
    
def _annotate_rwo_pvcs(namespace):
    click.echo("Annotating RWO PVCs")
    pvcs = [pvc for pvc in pyk8s.cl.persistentvolumeclaims.get(namespace=namespace) if "ReadWriteOnce" in pvc.status.accessModes]
    for pvc in pvcs:
        pvc.metadata.annotations["k8up.io/backup"] = "false"
        pvc.patch_()
    click.echo("RWO PVC annotation done")


def _snapshot_pod_creation(backup_name, namespace):

    k8up_snapshot_list_manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "k8up-snapshot-list-pod",
            "namespace": namespace,
            "labels": {
                "name": "k8up-snapshot-list-pod"
            }
        },
        "spec": {
            "restartPolicy": "Never",
            "containers": []
        }
    }

    container_details = {
        "name": "k8up-snapshot-list",
        "command": [
            "/usr/local/bin/restic",
            "snapshots"
        ],
        "args": [ "--tag",
          backup_name
        ],       
        "image": K8UP_IMAGE,
        "imagePullPolicy": "IfNotPresent",
        "resources": {},
    }

    container_details["env"] = [
        {
            "name": "RESTIC_PASSWORD",
            "valueFrom": {
                "secretKeyRef": {
                    "key": "password",
                    "name": "backup-repo"
                }
            }
        },
        {
            "name": "HOSTNAME",
            "value": "insights"
        },
        {
            "name": "STATS_URL"
        }
    ]

    credential_store = pyk8s.cl.secrets.get(name='backup-storage-creds', namespace=namespace)['data']
    provider = base64.b64decode(credential_store["provider"]).decode()

    if provider == 'azure':

        container_name = base64.b64decode(credential_store["container"]).decode()
        credentials = [
            {
                "name": "RESTIC_REPOSITORY",
                "value": "azure:" + container_name + ":/"
            },
            {
                "name": "AZURE_ACCOUNT_KEY",
                "valueFrom": {
                    "secretKeyRef": {
                        "key": "password",
                        "name": "backup-storage-creds"
                    }
                }
            },
            {
                "name": "AZURE_ACCOUNT_NAME",
                "valueFrom": {
                    "secretKeyRef": {
                        "key": "username",
                        "name": "backup-storage-creds"
                    }
                }
            }
        ]

    elif provider == "s3":

        bucket_name = base64.b64decode(credential_store["bucket"]).decode()
        endpoint = base64.b64decode(credential_store["endpoint"]).decode()

        credentials = [
            {
                "name": "RESTIC_REPOSITORY",
                "value": "s3:" + endpoint + "/" + bucket_name
            },
            {
                "name": "AWS_ACCESS_KEY_ID",
                "valueFrom": {
                    "secretKeyRef": {
                        "key": "username",
                        "name": "backup-storage-creds"
                    }
                }
            },
            {
                "name": "AWS_SECRET_ACCESS_KEY",
                "valueFrom": {
                    "secretKeyRef": {
                        "key": "password",
                         "name": "backup-storage-creds"
                    }
                }
            }
        ]

    for cred in credentials:
        container_details["env"].append(cred)

    k8up_snapshot_list_manifest["spec"]["containers"].append(container_details)

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


def _create_secrets(storage_details, restic_pw, namespace):

    # Create the storage credentials secret 
    secret = pyk8s.models.V1Secret()
    secret.metadata.name = 'backup-storage-creds'

    for key, value in storage_details.items():
        secret.set(key, value)

    try:
        secret.create_(namespace=namespace)
        click.echo(f'Secret created: {secret.metadata.name}')
    except Exception as e:
        traceback.print_exc()
        raise ClickException("%s" % (str(e)))

    # Ceate the restic password secret 
    secret.metadata.name = 'backup-repo'
    secret.set("password", restic_pw)
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
