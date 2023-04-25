import json
import typing
from io import BytesIO
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock

import pytest
import yaml
from click import ClickException, BaseCommand
from click.testing import CliRunner
from kubernetes.client import ApiException
from pytest_mock import MockerFixture
from urllib3 import HTTPResponse

from kxicli import main
from kxicli.commands import backup
from kxicli.commands.backup import Provider
from test_helm import fun_subprocess_run
from utils import IPATH_KUBE_COREV1API
from kubernetes.client import ApiException, V1Node, V1NodeList, V1ObjectMeta
from kubernetes import dynamic

default_env: dict = {
    'KUBECONFIG': str(Path(__file__).parent / 'files' / 'test-kube-config')
}


def _subprocess_run(
        *popenargs,
        input=None, capture_output=False, timeout=None, check=False, **kwargs
):
    _ = kwargs, popenargs, input, capture_output, timeout, check
    return CompletedProcess(args="fake_process", returncode=0, stdout='', stderr='')


def test_snapshot_pod_deletion(mocker):
    mocker.patch(IPATH_KUBE_COREV1API)
    backup._snapshot_pod_deletion(namespace="insights")


def test_snapshot_pod_deletion_fail(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.delete_namespaced_pod.side_effect = ApiException()
    with pytest.raises(ClickException):
        backup._snapshot_pod_deletion(namespace="insights")


def test_init(mocker: MockerFixture):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
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
    mock.return_value.list_node.return_value = [
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


def test_snapshot_list_from_logs(mocker: MockerFixture):
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

    mocker.patch('kubernetes.client.api.core_v1_api.CoreV1Api.list_namespaced_pod').return_value = MockHTTPResponse(
        body=BytesIO(data_str.encode())
    )
    mocker.patch('kubernetes.watch.watch._find_return_type').return_value = "V1PodList"
    mocker.patch('kubernetes.client.api.core_v1_api.CoreV1Api.read_namespaced_pod_log').return_value = "somelog"
    backup._snapshot_list_from_logs(namespace="insights")


def test_snapshot_list_from_logs_fail(mocker: MockerFixture):
    mocker.patch('kubernetes.client.api.core_v1_api.CoreV1Api.list_namespaced_pod').side_effect = ApiException(
        "something")
    with pytest.raises(ClickException):
        backup._snapshot_list_from_logs(namespace="insights")


def test_determine_provider_aks(mocker: MockerFixture):
    mocker.patch('kubernetes.client.api.core_v1_api.CoreV1Api.list_node').return_value = V1NodeList(items=[
        V1Node(metadata=V1ObjectMeta(name="aks"))
    ])

    assert backup._determine_provider() == Provider.AZURE


def test_determine_provider_eks(mocker: MockerFixture):
    mocker.patch('kubernetes.client.api.core_v1_api.CoreV1Api.list_node').return_value = V1NodeList(items=[
        V1Node(metadata=V1ObjectMeta(name="eks"))
    ])

    assert backup._determine_provider() == Provider.AWS


def test_determine_provider_gke(mocker: MockerFixture):
    mocker.patch('kubernetes.client.api.core_v1_api.CoreV1Api.list_node').return_value = V1NodeList(items=[
        V1Node(metadata=V1ObjectMeta(name="gke"))
    ])

    assert backup._determine_provider() == Provider.GCP


def test_determine_provider_fail(mocker: MockerFixture):
    mocker.patch('kubernetes.client.api.core_v1_api.CoreV1Api.list_node').side_effect = ApiException(
        "something")
    with pytest.raises(ClickException):
        backup._determine_provider()


@pytest.fixture
def create_mock_dynamic(mocker: MockerFixture):
    dynamic_patch = mocker.patch('kxicli.commands.backup.dynamic.DynamicClient')
    return dynamic_patch.return_value.resources.get.return_value.create


@pytest.fixture
def click_mock(mocker: MockerFixture):
    return mocker.patch('kxicli.commands.backup.click')


def test_snapshot_pod_creation(create_mock_dynamic, click_mock):
    metadata = MagicMock()
    metadata.name = "k8up-snapshot-list-pod"
    create_mock_dynamic.return_value = MagicMock(metadata=metadata)
    backup._snapshot_pod_creation(azure_blob_name="something", namespace="insights")
    create_mock_dynamic.assert_called()
    click_mock.echo.assert_called_with('Pod creation done: k8up-snapshot-list-pod\n')


def test_snapshot_pod_creation_fail(create_mock_dynamic):
    create_mock_dynamic.side_effect = Exception(
        "something")
    with pytest.raises(ClickException, match="Pod creation failed"):
        backup._snapshot_pod_creation(azure_blob_name="something", namespace="insights")
    create_mock_dynamic.assert_called()


def test_create_backup(create_mock_dynamic, click_mock):
    metadata = MagicMock()
    metadata.name = "something"
    create_mock_dynamic.return_value = MagicMock(metadata=metadata)
    backup._create_backup(backup_name="something", azure_blob_name="something", namespace="insights")
    create_mock_dynamic.assert_called()
    click_mock.echo.assert_called_with('K8up Backup CRD creation done: something')


def test_create_backup_fail(create_mock_dynamic):
    create_mock_dynamic.side_effect = Exception(
        "something")
    with pytest.raises(ClickException, match="CRD creation failed"):
        backup._create_backup(backup_name="something", azure_blob_name="something", namespace="insights")
    create_mock_dynamic.assert_called()
