import click
import pytest

from kxicli.commands.common import namespace
from utils import IPATH_KUBE_COREV1API, raise_conflict, raise_not_found


def test_create_namespace(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    assert namespace.create_namespace('test-ns') == None


def test_create_namespace_409_response_ok(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.create_namespace.side_effect = raise_conflict
    assert namespace.create_namespace('test-ns') == None


def test_create_namespace_404_response_raises_exception(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.create_namespace.side_effect = raise_not_found
    with pytest.raises(Exception) as e:
        namespace.create_namespace('test-ns')
    assert isinstance(e.value, click.ClickException)
    assert  e.value.message == f'Exception when trying to create namespace (404)\nReason: None\n'
