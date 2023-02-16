import base64
from typing import Optional

import click
import pytest
import requests_mock
import yaml
from kubernetes.client import V1Secret
from kubernetes.client.exceptions import ApiException
from pytest_mock import MockerFixture

from kxicli.commands.azure import default_insights_namespace, get_repo_url, get_values, \
    default_values_secret_data_name, default_docker_config_secret_name, default_values_secret_name
from kxicli.resources.helm import LocalHelmVersion, minimum_helm_version, HelmVersionChecked, \
    required_helm_version 
from kxicli.common import get_default_val as default_val
from utils import temp_file, mock_kube_secret_api, fake_docker_config_yaml, fake_docker_config_secret, return_none

local_minimum_helm_version: LocalHelmVersion = LocalHelmVersion(minimum_helm_version)
helm_version_checked: HelmVersionChecked = HelmVersionChecked(
    req_helm_version=required_helm_version,
    local_helm_version=local_minimum_helm_version
)
whatever_str: str = 'whatever'
fake_version: str = '1.2.3'
fake_chart_repo: str = 'kxinsightsprod.azurecr.io'
fake_chart_repo_url: str = f'oci://{fake_chart_repo}'
fake_values: dict = {
    'global': {
        'image': {
            'repository': f'{fake_chart_repo}/images/kx-insights'
        }
    }
}
fake_values_yaml: str = yaml.dump(fake_values)
fake_values_secret: V1Secret = V1Secret(
    data={
        default_values_secret_data_name: base64.b64encode(fake_values_yaml.encode('ascii'))
    }
)

fake_helm_version_checked: HelmVersionChecked = HelmVersionChecked(
    req_helm_version=required_helm_version,
    local_helm_version=LocalHelmVersion(minimum_helm_version)
)

# mocks

def read_secret(namespace: str, name: str) -> Optional[V1Secret]:
    if namespace == default_insights_namespace and name == default_values_secret_name:
        return fake_values_secret
    elif name == default_docker_config_secret_name:
        return fake_docker_config_secret
    return None

# tests

def test_get_repo_url():
    assert get_repo_url(fake_values_yaml) == fake_chart_repo_url


def test_get_values_none_no_secret(mocker: MockerFixture):
    mock_kube_secret_api(mocker, read=return_none)
    with pytest.raises(click.ClickException):
        get_values(
            values_file=None,
        )


def test_get_values_none_but_secret(mocker: MockerFixture):
    mock_kube_secret_api(mocker, read=read_secret)
    assert get_values(
            values_file=None,
    ) == fake_values_yaml


def test_get_values_file_only():
    with temp_file(file_name='values.yaml') as values_file:
        with open(values_file, mode='w') as vf:
            vf.write(fake_values_yaml)
        assert get_values(
            values_file=values_file,
        ) == fake_values_yaml


def test_get_values_file_not_exists():
    with pytest.raises(FileNotFoundError):
        with temp_file(file_name='values.yaml') as values_file:
            get_values(
                values_file=values_file,
            )
