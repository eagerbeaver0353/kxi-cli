from typing import Optional

import click
import pytest
import yaml
from kubernetes.client import V1Secret
from pytest_mock import MockerFixture

from kxicli.commands.azure import get_repo_url, get_values, \
    default_docker_config_secret_name
from kxicli.resources.helm import LocalHelmVersion, minimum_helm_version, HelmVersionChecked, \
    required_helm_version
import utils

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

fake_helm_version_checked: HelmVersionChecked = HelmVersionChecked(
    req_helm_version=required_helm_version,
    local_helm_version=LocalHelmVersion(minimum_helm_version)
)

# mocks

def read_secret(namespace: str, name: str) -> Optional[V1Secret]:
    if name == default_docker_config_secret_name:
        return utils.fake_docker_config_secret
    return None

# tests

def test_get_repo_url():
    assert get_repo_url(fake_values_yaml) == fake_chart_repo_url

def test_get_values_none_but_release_values(mocker: MockerFixture):
    data = {'a': 1}
    utils.mock_helm_get_values(mocker, data)
    assert get_values(
            values_file=None,
    ) == yaml.safe_dump(data)


def test_get_values_file_only():
    with utils.temp_file(file_name='values.yaml') as values_file:
        with open(values_file, mode='w') as vf:
            vf.write(fake_values_yaml)
        assert get_values(
            values_file=values_file,
        ) == fake_values_yaml


def test_get_values_file_not_exists():
    with pytest.raises(FileNotFoundError):
        with utils.temp_file(file_name='values.yaml') as values_file:
            get_values(
                values_file=values_file,
            )
