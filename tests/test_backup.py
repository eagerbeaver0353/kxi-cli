import json
import typing
from io import BytesIO
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock
import pyk8s

import pytest
import yaml
from click import ClickException, BaseCommand
from click.testing import CliRunner
from pytest_mock import MockerFixture
from urllib3 import HTTPResponse

from kxicli import main
from kxicli.commands import backup
from kxicli.commands.backup import Provider
from test_helm import fun_subprocess_run
from utils import IPATH_KUBE_COREV1API

default_env: dict = {
    'KUBECONFIG': str(Path(__file__).parent / 'files' / 'test-kube-config')
}


def _subprocess_run(
        *popenargs,
        input=None, capture_output=False, timeout=None, check=False, **kwargs
):
    _ = kwargs, popenargs, input, capture_output, timeout, check
    return CompletedProcess(args="fake_process", returncode=0, stdout='', stderr='')


def test_snapshot_pod_deletion(k8s):
    backup._snapshot_pod_deletion(namespace="insights")


def test_snapshot_pod_deletion_fail(k8s):
    k8s.pods.read().delete_.side_effect = pyk8s.exceptions.ApiException()

    with pytest.raises(ClickException):
        backup._snapshot_pod_deletion(namespace="insights")


def test_init(mocker: MockerFixture, k8s: MagicMock):
    urllib_mock = mocker.patch('urllib.request.urlopen')
    urllib_mock.return_value = yaml.safe_dump_all([{
        'apiVersion': 'v1',
        'kind': 'Pod',
        'metadata': {
            'name': 'my-pod'
        },
        'spec': {
            'containers': [
                {
                    'name': 'my-container',
                    'image': 'nginx'
                }
            ]
        }
    }])
    mocker.patch(fun_subprocess_run, _subprocess_run)
    k8s.nodes.get.return_value = [
        {
            'metadata': {
                'name': backup.AZURE_NODENAME_PREFIX
            }
        }
    ]
    runner = CliRunner()
    result = runner.invoke(
        typing.cast(BaseCommand, main.cli),
        args=[
            'backup',
            'init',
            '--az-stg-acc-name', 'az_stg_acc_name',
            '--az-stg-acc-key', 'az_stg_acc_key',
            '--restic-pw', 'restic_pw',
            '--namespace', 'namespace',
            '--obj-store-provider', backup.Provider.AZURE.value
        ],
        env=default_env
    )
    assert result.exit_code == 0


def test_set_backup(mocker: MockerFixture, k8s: MagicMock):
    # Given an RWO and an RWM pvc
    rwo = pyk8s.models.V1PersistentVolumeClaim.parse_obj({
                'apiVersion': 'v1',
                'kind': 'PersistentVolumeClaim',
                'metadata': {
                    'name': 'weatherdb-hdb',
                    'namespace': 'test-namespace',
                },
                'spec': {
                    'accessModes': [
                        'ReadWriteOnce'
                        ]
                },
                'status': {
                    'accessModes': [
                        'ReadWriteOnce'
                        ]
                }
            })

    rwm = pyk8s.models.V1PersistentVolumeClaim.parse_obj({
                'apiVersion': 'v1',
                'kind': 'PersistentVolumeClaim',
                'metadata': {
                    'name': 'weatherdb-hdb',
                    'namespace': 'test-namespace',
                },
                'spec': {
                    'accessModes': [
                        'ReadWriteMany'
                        ]
                },
                'status': {
                    'accessModes': [
                        'ReadWriteMany'
                        ]
                }
            })

    # When K8s returns an rwo and an rwm volume
    k8s.persistentvolumeclaims.get.return_value = [
        rwo, rwm
    ]
    
    # Given the K8s API accepts the patch
    pyk8s.cl.get_api().patch.side_effect = lambda *args, **kwargs: kwargs["body"]
    
    runner = CliRunner()
    result = runner.invoke(
        typing.cast(BaseCommand, main.cli),
        args=[
            'backup',
            'set-backup',
            '--backup-name', 'test_backup_name',
            '--azure-blob-name', 'test_blob_name'
        ],
        env=default_env
    )
    
    # THEN Assert patch was only called once
    pyk8s.cl.get_api().patch.assert_called_once()
    
    # The RWO volume is patched to have this annotation
    assert rwo.metadata.annotations["k8up.io/backup"] == "false"
    pyk8s.cl.get_api().patch.assert_called_once_with(name="weatherdb-hdb", body=rwo)
    
    # Then the RWM volume is not patched
    assert len(rwm.metadata.annotations) == 0
    
    # And the Backup CRD was called
    pyk8s.cl.get_api(kind="Backup").create.assert_called_once()
    
    assert result.exit_code == 0

class MockHTTPResponse(HTTPResponse):
    def __init__(
            self, body, headers=None, status=0, version=0, reason=None, strict=0, preload_content=True,
            decode_content=True, original_response=None, pool=None, connection=None, msg=None, retries=None,
            enforce_content_length=False, request_method=None, request_url=None, auto_close=True):
        super().__init__(
            body, headers, status, version, reason, strict, preload_content, decode_content,
            original_response, pool, connection, msg, retries, enforce_content_length, request_method,
            request_url, auto_close)
        self._fp: BytesIO = body

    def stream(self, amt=2 ** 16, decode_content=None):
        data = self.data
        yield data


def test_snapshot_list_from_logs(mocker: MockerFixture, k8s: MagicMock):
    data_str = json.dumps({
        "type": "ADDED",
        "object": {
            "kind": "Pod",
            "apiVersion": "v1",
            "metadata": {
                "resourceVersion": "124579"
            },
            "status": {
                "phase": "Succeeded"
            }}
    }) + "\n"

    pod = pyk8s.models.V1Pod()
    mocker.patch.object(pod, "wait_until_status")
    mocker.patch.object(pod, "logs", return_value="somelog")
    backup._snapshot_list_from_logs(pod)


def test_snapshot_list_from_logs_fail(mocker: MockerFixture, k8s: MagicMock):
    pod = pyk8s.models.V1Pod()
    mocker.patch.object(pod, "wait_until_status", side_effect=pyk8s.exceptions.ApiException("something"))
    with pytest.raises(pyk8s.exceptions.ApiException):
        backup._snapshot_list_from_logs(pod)


def test_determine_provider_aks(k8s: MagicMock):
    k8s.nodes.get.return_value = [pyk8s.models.V1Node(metadata=pyk8s.models.V1ObjectMeta(name="aks"))]

    assert backup._determine_provider() == Provider.AZURE


def test_determine_provider_eks(k8s: MagicMock):
    k8s.nodes.get.return_value = [pyk8s.models.V1Node(metadata=pyk8s.models.V1ObjectMeta(name="eks"))]

    assert backup._determine_provider() == Provider.AWS


def test_determine_provider_gke(k8s: MagicMock):
    k8s.nodes.get.return_value = [pyk8s.models.V1Node(metadata=pyk8s.models.V1ObjectMeta(name="gke"))]

    assert backup._determine_provider() == Provider.GCP


def test_determine_provider_fail(mocker: MockerFixture, k8s: MagicMock):
    k8s.nodes.get.side_effect = pyk8s.exceptions.ApiException("something")
    with pytest.raises(ClickException):
        backup._determine_provider()


@pytest.fixture
def click_mock(mocker: MockerFixture):
    return mocker.patch('kxicli.commands.backup.click')


def test_snapshot_pod_creation(k8s, click_mock):
    k8s.pods.create.side_effect = lambda x: pyk8s.models.V1Pod.parse_obj(x)
    backup._snapshot_pod_creation(azure_blob_name="something", namespace="insights")
    click_mock.echo.assert_called_with('Pod creation done: k8up-snapshot-list-pod\n')
    k8s.pods.create.assert_called()


def test_snapshot_pod_creation_fail(k8s):
    k8s.pods.create.side_effect = Exception("something")
    with pytest.raises(ClickException, match="Pod creation failed"):
        backup._snapshot_pod_creation(azure_blob_name="something", namespace="insights")
    k8s.pods.create.assert_called()


def test_create_backup(k8s, click_mock):
    k8s.get_api(kind="Backup").create.side_effect = lambda x: pyk8s.models.V1Pod.parse_obj(x)
    backup._create_backup(backup_name="something", azure_blob_name="something", namespace="insights")
    k8s.get_api(kind="Backup").create.assert_called()
    click_mock.echo.assert_called_with('K8up Backup CRD creation done: something')


def test_create_backup_fail(k8s):
    k8s.get_api(kind="Backup").create.side_effect = Exception("something")
    with pytest.raises(ClickException, match="CRD creation failed"):
        backup._create_backup(backup_name="something", azure_blob_name="something", namespace="insights")
    k8s.get_api(kind="Backup").create.assert_called()
