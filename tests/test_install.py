"""This install test is meant to unit test the individual functions in the install command"""
import base64
import copy
import io
import json
import kubernetes as k8s
import pytest
import subprocess
import yaml
import click

from kxicli import common
from kxicli.commands import install
from kxicli.resources import secret
from utils import IPATH_KUBE_COREV1API, temp_file, test_secret_data, test_secret_type, test_secret_key, \
    mock_kube_deployment_api, mocked_kube_deployment_list, mock_kube_secret_api, mocked_read_namespaced_secret, \
    raise_conflict, raise_not_found, mock_validate_secret, mock_helm_env, mock_helm_get_values,  mocked_helm_repo_list, \
    return_none, fake_docker_config_yaml, test_val_file
from test_install_e2e import mocked_read_namespaced_secret_return_values, test_vals, mocked_read_secret, mocked_installed_chart_json
from const import test_user, test_pass, test_lic_file, test_chart_repo_name, test_chart_repo_url

# Common test parameters
test_ns = 'test-ns'
test_repo = 'test.kx.com'
test_secret = 'test-secret'
test_key = install.gen_private_key()
test_cert = install.gen_cert(test_key)
test_values_yaml = 'values.yaml'
test_values_keys = ('values.yaml',)

common.config.load_config("default")

# Constants for common import paths
SYS_STDIN = 'sys.stdin'

fun_subprocess_check_output = 'subprocess.check_output'


def populate(secret, **kwargs):
    secret.data = kwargs.get('data')
    return secret


# These are used to mock helm calls to list deployed releases
# helm list --filter insights --deployed -o json
def mocked_helm_list_returns_valid_json(base_command):
    return '[{"name":"insights","namespace":"testNamespace","revision":"1","updated":"2022-02-23 10:39:53.7668809 +0000 UTC","status":"deployed","chart":"insights-0.11.0-rc.39","app_version":"0.11.0-rc.8"}]'


def mocked_helm_list_returns_empty_json(base_command):
    return '[]'


def mocked_helm_search_returns_valid_json(base_command, check=True, capture_output=True, text=True):
    return install.subprocess.CompletedProcess(
        args=base_command,
        returncode=0,
        stdout='[{"name":"kx-insights/kxi-operator","version":"1.3.0","app_version":"1.3.0","description":"KX Insights Operator"}]\n'
    )


def mocked_helm_search_returns_valid_json_rc(base_command, check=True, capture_output=True, text=True):
    return install.subprocess.CompletedProcess(
        args=base_command,
        returncode=0,
        stdout='[{"name":"kx-insights/kxi-operator","version":"1.3.0-rc.40","app_version":"1.3.0","description":"KX Insights Operator"}]\n'
    )

def mocked_helm_search_returns_valid_json_optional_multiple_versions(base_command, check=True, capture_output=True, text=True):
    return install.subprocess.CompletedProcess(
        args=base_command,
        returncode=0,
        stdout='[{"name":"kx-insights/kxi-operator","version":"1.3.0-rc.32","app_version":"1.3.0","description":"KX Insights Operator"}, {"name":"kx-insights/kxi-operator","version":"1.3.1-rc.1","app_version":"1.3.1-rc.1","description":"KX Insights Operator"}]\n'
    )

def mocked_helm_search_returns_empty_json(base_command, check=True, capture_output=True, text=True):
    return install.subprocess.CompletedProcess(
        args=base_command,
        returncode=0,
        stdout='[]\n'
    )


def test_get_secret_body_string_data_parameter():
    sdata = {'a': 'b'}

    expected = k8s.client.V1Secret()
    expected.metadata = k8s.client.V1ObjectMeta(namespace=test_ns, name=test_secret)
    expected.type = test_secret_type
    expected.string_data = sdata

    s = secret.Secret(test_ns, test_secret, test_secret_type, string_data=sdata)

    assert s.get_body() == expected


def test_get_secret_body_data_parameter():
    data = {'a': 'b'}

    expected = k8s.client.V1Secret()
    expected.metadata = k8s.client.V1ObjectMeta(namespace=test_ns, name=test_secret)
    expected.type = test_secret_type
    expected.data = data
    s = secret.Secret(test_ns, test_secret, test_secret_type, data=data)

    assert s.get_body() == expected


def test_create_docker_config():
    test_cfg = {
        'auths': {
            test_repo: {
                'username': test_user,
                'password': test_pass,
                'auth': base64.b64encode(f'{test_user}:{test_pass}'.encode()).decode('ascii')
            }
        }
    }

    assert install.create_docker_config(test_repo, test_user, test_pass) == test_cfg


def test_create_docker_secret(mocker):
    mock_kube_secret_api(mocker)

    test_cfg = install.create_docker_config(test_repo, test_user, test_pass)

    s = secret.Secret(test_ns, test_secret, install.SECRET_TYPE_DOCKERCONFIG_JSON, install.IMAGE_PULL_KEYS)
    res = install.populate_docker_config_secret(s, test_cfg).get_body()

    assert res.type == 'kubernetes.io/dockerconfigjson'
    assert res.metadata.name == test_secret
    assert '.dockerconfigjson' in res.data


def test_get_docker_config_secret(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_secret)
    assert install.get_docker_config_secret(
        namespace='test-namespace',
        secret_name=common.get_default_val('image.pullSecret')
        
    ) == fake_docker_config_yaml


def test_get_docker_config_secret_fail(mocker):
    mock_kube_secret_api(mocker, read=return_none)
    with pytest.raises(click.ClickException):
        install.get_docker_config_secret(
        namespace='test-namespace',
        secret_name=common.get_default_val('image.pullSecret')
        )

def test_create_license_secret_encoded(mocker):
    mock_kube_secret_api(mocker)

    s = secret.Secret(test_ns, test_secret, install.SECRET_TYPE_OPAQUE, install.LICENSE_KEYS)
    s, _ = install.populate_license_secret(s, test_lic_file, True)
    res = s.get_body()

    assert res.type == test_secret_type
    assert res.metadata.name == test_secret
    assert 'license' in res.string_data
    with open(test_lic_file, 'rb') as license_file:
        assert base64.b64decode(res.string_data['license']) == license_file.read()


def test_create_license_secret_decoded(mocker):
    mock_kube_secret_api(mocker)

    s = secret.Secret(test_ns, test_secret, install.SECRET_TYPE_OPAQUE, install.LICENSE_KEYS)
    s, _ = install.populate_license_secret(s, test_lic_file, False)
    res = s.get_body()

    assert res.type == test_secret_type
    assert res.metadata.name == test_secret
    assert 'license' in res.data
    with open(test_lic_file, 'rb') as license_file:
        assert base64.b64decode(res.data['license']) == license_file.read()


def test_create_tls_secret(mocker):
    mock_kube_secret_api(mocker)

    s = secret.Secret(test_ns, test_secret, install.SECRET_TYPE_TLS)
    s = install.populate_tls_secret(s, test_cert, test_key)
    res = s.get_body()

    assert res.type == 'kubernetes.io/tls'
    assert res.metadata.name == test_secret
    assert 'tls.crt' in res.data
    assert 'tls.key' in res.data


def test_create_keycloak_secret_from_cli_config(mocker):
    mock_kube_secret_api(mocker)
    admin_pass = 'test-keycloak-admin-password'
    management_pass = 'test-keycloak-management-password'
    common.config.config['default']['keycloak.admin.password'] = admin_pass
    common.config.config['default']['keycloak.management.password'] = management_pass

    s = secret.Secret(test_ns, test_secret, install.SECRET_TYPE_OPAQUE)
    s = install.populate_keycloak_secret(s)
    res = s.get_body()

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert 'admin-password' in res.data
    assert 'management-password' in res.data
    assert base64.b64decode(res.data['admin-password']).decode('ascii') == admin_pass
    assert base64.b64decode(res.data['management-password']).decode('ascii') == management_pass
    common.config.load_config('default')


def test_create_postgres_secret_from_cli_config(mocker):
    mock_kube_secret_api(mocker)
    postgres_pass = 'test-postgres-admin-password'
    user_pass = 'test-postgres-user-password'
    common.config.config['default']['postgresql.postgres.password'] = postgres_pass
    common.config.config['default']['postgresql.user.password'] = user_pass

    s = secret.Secret(test_ns, test_secret, install.SECRET_TYPE_OPAQUE)
    s = install.populate_postgresql_secret(s)
    res = s.get_body()

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert 'postgresql-postgres-password' in res.data
    assert 'postgres-password' in res.data
    assert 'postgresql-password' in res.data
    assert 'password' in res.data
    
    assert base64.b64decode(res.data['postgresql-postgres-password']).decode('ascii') == postgres_pass
    assert base64.b64decode(res.data['postgres-password']).decode('ascii') == postgres_pass
    assert base64.b64decode(res.data['postgresql-password']).decode('ascii') == user_pass
    assert base64.b64decode(res.data['password']).decode('ascii') == user_pass
    common.config.load_config('default')


def test_read_secret_returns_k8s_secret(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret)

    s = secret.Secret(test_ns, test_secret)
    res = s.read()

    assert res.type == test_secret_type
    assert res.metadata.name == test_secret
    assert res.data == test_secret_data


def test_read_secret_returns_empty_when_does_not_exist(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.read_namespaced_secret.side_effect = raise_not_found
    s = secret.Secret(test_ns, test_secret)
    res = s.read()

    assert res == None


def test_copy_secret(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    assert install.copy_secret(test_secret, test_ns, 'to_ns') == None


def test_copy_secret_404_exception_when_reading_secret(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.read_namespaced_secret.side_effect = raise_not_found
    with pytest.raises(Exception) as e:
        install.copy_secret(test_secret, test_ns, 'to_ns')
    assert isinstance(e.value, click.ClickException)
    assert 'Exception when trying to get secret (404)\nReason: None\n' in e.value.message


def test_copy_secret_404_exception_when_creating_secret(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.create_namespaced_secret.side_effect = raise_not_found
    with pytest.raises(Exception) as e:
        install.copy_secret(test_secret, test_ns, 'to_ns')
    assert isinstance(e.value, click.ClickException)
    assert 'Exception when trying to create secret (404)\nReason: None\n' in e.value.message


def test_copy_secret_409_exception_when_creating_secret_does_not_raise_exception(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.create_namespaced_secret.side_effect = raise_conflict
    assert install.copy_secret(test_secret, test_ns, 'to_ns') == None


def test_get_secret_returns_decoded_secret(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret)

    s = secret.Secret(test_ns, test_secret)
    res = install.get_secret(s, test_secret_key)

    assert res == base64.b64decode(test_secret_data[test_secret_key]).decode('ascii')


def test_get_secret_when_does_not_exist(mocker):
    mock_kube_secret_api(mocker)
    s = secret.Secret(test_ns, test_secret)
    res = install.get_secret(s, test_values_yaml)

    assert res == None


def test_get_secret_when_key_does_not_exist(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)
    s = secret.Secret(test_ns, test_secret)
    res = install.get_secret(s, 'a_bad_key')

    assert res == None


def test_patch_secret_returns_updated_k8s_secret(mocker):
    mock_kube_secret_api(mocker)
    s = secret.Secret(test_ns, test_secret, test_secret_type)
    s.data = {"secret_key": "new_value"}
    res = s.patch()

    assert res.type == test_secret_type
    assert res.metadata.name == test_secret
    assert res.data == s.data


def test_get_operator_version_returns_operator_version_if_passed_regardless_of_rc():
    non_rc = install.get_operator_version('kxi-insights', '1.2.3', '4.5.6')
    rc = install.get_operator_version('kxi-insights', '1.2.3-rc.1', '4.5.6')

    assert non_rc == '4.5.6'
    assert rc == '4.5.6'

def get_minor_version_returns_minor_version_from_semver():
    assert install.get_minor_version('1.0.0') == '1.0'
    assert install.get_minor_version('1.2.3') == '1.2'
    assert install.get_minor_version('1.2.3-rc.50') == '1.2'

def mocked_subprocess_get_operator_version(chart_repo_name, insights_version, rc_version):
        if rc_version:
            return f'{insights_version}-rc.40'
        else:
            return insights_version

def mocked_subprocess_get_operator_version_inc(chart_repo_name, insights_version, rc_version):
        return '1.5.0'

def mocked_subprocess_get_operator_version_none(chart_repo_name, insights_version, rc_version):
        return ''
    
def test_get_operator_version_returns_latest_minor_version(mocker):
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json)
    assert install.get_operator_version('kxi-insights', '1.3.0', None) == '1.3.0'

def test_get_operator_version_returns_latest_minor_version_multiple_versions(mocker):
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json_optional_multiple_versions)
    assert install.get_operator_version('kxi-insights', '1.3.0', None) == '1.3.1-rc.1'

def test_get_operator_version_returns_latest_minor_version_rc(mocker):
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json_rc)
    assert install.get_operator_version('kxi-insights', '1.3.0-rc.30', None) == '1.3.0-rc.40'

def test_get_operator_version_returns_none_when_not_found(mocker):
    mocker.patch('subprocess.run', mocked_helm_search_returns_empty_json)
    assert install.get_operator_version('kxi-insights', '5.6.7', None) == None


def test_get_installed_charts_returns_chart_json(mocker):
    mocker.patch(fun_subprocess_check_output, mocked_helm_list_returns_valid_json)
    assert install.get_installed_charts('insights', test_ns) == json.loads(mocked_helm_list_returns_valid_json(''))


def test_insights_installed_returns_true_when_already_exists(mocker):
    mocker.patch(fun_subprocess_check_output, mocked_helm_list_returns_valid_json)
    assert install.insights_installed('insights', test_ns) == True


def test_insights_installed_returns_false_when_does_not_exist(mocker):
    mocker.patch(fun_subprocess_check_output, mocked_helm_list_returns_empty_json)
    assert install.insights_installed('insights', test_ns) == False


def test_helm_repo_list_when_repo_exists(mocker):
    expected_result = mocked_helm_repo_list(test_chart_repo_name, test_chart_repo_url)
    helm_response = subprocess.CompletedProcess(args=['helm', 'repo', 'list', '--output', 'json'], returncode=0, stdout=json.dumps(expected_result))
    mocker.patch('subprocess.run').return_value = helm_response
    assert install.helm_repo_list() == expected_result


def test_helm_repo_list_returns_empty_list_when_repo_search_errors(mocker):
    mocker.patch('subprocess.run').side_effect = subprocess.CalledProcessError(1, ['helm', 'repo', 'list'])
    assert install.helm_repo_list() == []


def test_insights_check_helm_repo_exists(mocker):
    mocker.patch('kxicli.commands.install.helm_repo_list', lambda: mocked_helm_repo_list(test_chart_repo_name, test_chart_repo_url))
    assert install.check_helm_repo_exists(test_chart_repo_name) == None
    with pytest.raises(Exception) as e:
        install.check_helm_repo_exists('a-different-repo')
    assert isinstance(e.value, click.ClickException)
    assert 'Cannot find local chart repo a-different-repo' in e.value.message


def test_insights_check_helm_repo_exists_returns_error_when_repo_does_not_exist(mocker):
    mocker.patch('subprocess.run').side_effect = subprocess.CalledProcessError(1, ['helm', 'repo', 'list'])
    with pytest.raises(Exception) as e:
        install.check_helm_repo_exists(test_chart_repo_name)
    assert isinstance(e.value, click.ClickException)
    assert f'Cannot find local chart repo {test_chart_repo_name}' in e.value.message


def test_get_installed_operator_versions_returns_helm_chart_version(mocker):
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    assert install.get_installed_operator_versions('kx-operator') == (['1.2.3'], ['test-helm-name'])


def test_get_installed_operator_versions_returns_helm_chart_version_when_does_not_exist(mocker):
    mock_kube_deployment_api(mocker)
    assert install.get_installed_operator_versions('kx-operator') == ([], [])


def test_sanitize_auth_url():
    https_replaced = install.sanitize_auth_url('https://keycloak.keycloak.svc.cluster.local/auth/')
    trailing_slash = install.sanitize_auth_url('https://keycloak.keycloak.svc.cluster.local/auth')
    prepend_http = install.sanitize_auth_url('keycloak.keycloak.svc.cluster.local/auth')

    expected = 'http://keycloak.keycloak.svc.cluster.local/auth/'
    assert https_replaced == expected
    assert trailing_slash == expected
    assert prepend_http == expected


def test_get_image_and_license_secret_from_values_returns_defaults():
    assert install.get_image_and_license_secret_from_values({}, None, None) == (
    'kxi-nexus-pull-secret', 'kxi-license')

def test_get_image_and_license_secret_from_values_args_overrides_values_dict():
    assert install.get_image_and_license_secret_from_values(test_vals, 
                                                            'image-pull-from-arg',
                                                            'license-from-arg') == (
           'image-pull-from-arg', 'license-from-arg')

def test_get_image_and_license_secret_returns_error_when_invalid_dict_passed():
    with pytest.raises(Exception) as e:
        install.get_image_and_license_secret_from_values(test_lic_file, None, None)
    assert isinstance(e.value, click.ClickException)
    assert f'Invalid values' in e.value.message


def test_get_missing_key_with_no_dict_returns_all_keys():
    keys = ('a','b')
    assert list(keys) == secret.Secret(test_ns, test_secret, required_keys = keys).get_missing_keys(None)


def test_get_missing_key_with_key_missing():
    assert ['a'] == secret.Secret(test_ns, test_secret, required_keys = ('a','b')).get_missing_keys({'b': 2, 'c': 3})


def test_get_missing_key_with_no_key_missing():
    assert [] == secret.Secret(test_ns, test_secret, required_keys = ('a', 'b')).get_missing_keys({'a': 1, 'b': 2})


def test_validate_secret_when_no_secret_exists(mocker):
    mock_kube_secret_api(mocker)
    assert (False, True, []) == secret.Secret(test_ns, test_secret, test_secret_type, ['test']).validate()


def test_validate_secret_when_missing_a_key(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret)
    assert (True, False, ['test']) == secret.Secret(test_ns, test_secret, test_secret_type, ['test']).validate()


def test_validate_secret_when_incorrect_type(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret)
    assert (True, False, []) == secret.Secret(test_ns, test_secret, install.SECRET_TYPE_TLS, (test_secret_key,)).validate()


def test_ensure_secret_when_does_not_exist(mocker):
    mock_kube_secret_api(mocker)

    key = 'a'
    secret_data = {key: 1}
    s = secret.Secret(test_ns, test_secret, test_secret_type)
    res = install.ensure_secret(s, populate, data=secret_data)

    assert res.type == test_secret_type
    assert res.name == test_secret
    assert key in res.data
    assert res.data[key] == 1


def test_ensure_secret_when_secret_exists_and_is_valid(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret)
    s = secret.Secret(test_ns, test_secret)
    res = install.ensure_secret(s, populate, data=test_secret_data)

    assert res.type is None
    assert res.name == test_secret
    # populate function should not be called to update the data because it's already valid
    assert res.data is None

def test_ensure_secret_when_secret_exists_but_is_invalid_w_overwrite(mocker, monkeypatch):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret)
    mock_validate_secret(mocker, is_valid=False)
    
    # patch stdin to 'n' for the prompt rejecting secret overwrite
    monkeypatch.setattr(SYS_STDIN, io.StringIO('y'))

    new_key = 'xyz'
    new_data = {new_key: 123}

    s = secret.Secret(test_ns, test_secret, test_secret_type, data=test_secret_data)
    res = install.ensure_secret(s, populate, data=new_data)

    assert res.type == test_secret_type
    assert res.name == test_secret
    assert new_key in res.data
    assert res.data[new_key] == new_data[new_key]


def test_ensure_secret_when_secret_exists_but_is_invalid_w_no_overwrite(mocker, monkeypatch):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret)
    mock_validate_secret(mocker, is_valid=False)

    # patch stdin to 'n' for the prompt rejecting secret overwrite
    monkeypatch.setattr(SYS_STDIN, io.StringIO('n'))

    s = secret.Secret(test_ns, test_secret, test_secret_type, data=test_secret_data)
    res = install.ensure_secret(s, populate, data={'a': 1})

    assert res.type == test_secret_type
    assert res.name == test_secret
    assert test_secret_key in res.data
    assert res.data[test_secret_key] == test_secret_data[test_secret_key]


def test_create_secret_returns_k8s_secret(mocker):
    mock_kube_secret_api(mocker)

    s = secret.Secret(test_ns, test_secret, test_secret_type, data=test_secret_data)
    res = s.create()

    assert res.metadata.namespace == test_ns
    assert res.type == test_secret_type
    assert res.metadata.name == test_secret
    assert res.data == test_secret_data


def test_create_secret_returns_exception(mocker):
    mock_kube_secret_api(mocker, create=raise_not_found)
    s = secret.Secret(test_ns, test_secret, test_secret_type, data=test_secret_data)
    res = s.create()

    assert isinstance(res, k8s.client.exceptions.ApiException)
    assert res.status == 404


def test_patch_secret_returns_exception(mocker):
    mock_kube_secret_api(mocker, patch=raise_not_found)
    s = secret.Secret(test_ns, test_secret, test_secret_type, data=test_secret_data)
    res = s.patch()

    assert isinstance(res, k8s.client.exceptions.ApiException)
    assert res.status == 404


def test_exists_returns_true_when_exists(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret)
    s = secret.Secret(test_ns, test_secret, test_secret_type, data=test_secret_data)
    assert s.exists()


def test_exists_returns_false_when_does_not_exist(mocker):
    mock_kube_secret_api(mocker)
    s = secret.Secret(test_ns, test_secret, test_secret_type, data=test_secret_data)
    assert s.exists() == False


def test_read_cache_crd_from_file_throws_yaml_error(mocker):
    mock_helm_env(mocker)

    # mock data returned from tar extraction
    mocker.patch('kxicli.common.extract_files_from_tar', return_value=['abc: 123\n    def: 456'])
    with pytest.raises(Exception) as e:
        install.read_cached_crd_files(
            '1.2.3',
            'kxi-operator',
            [install.CRD_FILES[0]]
            )

    assert isinstance(e.value, click.ClickException)
    assert 'Failed to parse custom resource definition file' in e.value.message

def test_filter_max_operator_version_rcTrue():
    data = [{'version': '1.0.0-rc.1'}, {'version': '1.0.0-rc.2'}, {'version': '1.0.0-rc.3'}]
    insights_version = '1.0.0'
    rc_version = True
    assert install.filter_max_operator_version(data, insights_version, rc_version) == '1.0.0-rc.3'

def test_filter_max_operator_version_rcFalse():
    data = [{'version': '1.0.0-rc.1'}, {'version': '1.0.0-rc.2'}, {'version': '1.0.0'}]
    insights_version = '1.0.0'
    rc_version = False
    assert install.filter_max_operator_version(data, insights_version, rc_version) == '1.0.0'

def test_filter_max_operator_version_no_match():
    data = [{'version': '1.0.0-rc.1'}, {'version': '1.0.0-rc.2'}, {'version': '1.0.1'}]
    insights_version = '2.0.0'
    rc_version = True
    assert install.filter_max_operator_version(data, insights_version, rc_version) == ''

def test_check_for_operator_install_returns_version_to_install(mocker):
    # Operator not already installed, compatible version avaliable on repo
    mock_helm_env(mocker)
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json)
    mock_kube_deployment_api(mocker)
    assert install.check_for_operator_install('kx-insights', 'insights', '1.3.0', None, force=True) == (True, False, '1.3.0', 'kx-insights', [])


def test_check_for_operator_install_errors_when_operator_repo_charts_not_compatible(mocker):
    # Operator not already installed, no compatible version avaliable on repo. Error returned
    mock_helm_env(mocker)
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json)
    mock_kube_deployment_api(mocker)
    with pytest.raises(Exception) as e:
        install.check_for_operator_install('kx-insights', 'insights', '1.8.0', None, True)
    assert isinstance(e.value, click.ClickException)
    assert 'Compatible version of operator not found' in e.value.message


def test_check_for_operator_install_does_not_install_when_no_repo_charts_available(mocker):
    # Operator already installed, no compatible version avaliable on repo
    mocker.patch('subprocess.run', mocked_helm_search_returns_empty_json)
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    with pytest.raises(Exception) as e:
        install.check_for_operator_install('kx-insights', 'insights', '1.8.0', None, True)
    assert isinstance(e.value, click.ClickException)
    assert 'Compatible version of operator not found' in e.value.message

def test_check_for_operator_install_errors_when_installed_operator_not_compitible(mocker):
    # Incompatiable operator already installed, no version avaliable on repo. Error returned
    mocker.patch('subprocess.run', mocked_helm_search_returns_empty_json)
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    with pytest.raises(Exception) as e:
        install.check_for_operator_install('kx-insights', 'insights', '1.8.0', None, True)
    assert isinstance(e.value, click.ClickException)
    assert 'Compatible version of operator not found' in e.value.message


def test_check_for_operator_install_when_installed_and_available_operators_not_compitible(mocker):
    # Incompatiable operator already installed, no compatible version avaliable on repo. Error returned    
    mock_helm_env(mocker)
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json)
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    with pytest.raises(Exception) as e:
        install.check_for_operator_install('kx-insights', 'insights', '1.4.0', None, True)
    assert isinstance(e.value, click.ClickException)
    assert 'Compatible version of operator not found' in e.value.message


def test_check_for_operator_install_when_provided_insights_and_operators_not_compitible(mocker):
    # Provided versions of operator and insights do not match minor versions
    mocker.patch('subprocess.run', mocked_helm_search_returns_empty_json)
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    with pytest.raises(Exception) as e:
        install.check_for_operator_install('kx-insights', 'insights', '1.3.0', '1.4.0', True)
    assert isinstance(e.value, click.ClickException)
    assert 'kxi-operator version 1.4.0 is incompatible with insights version 1.3.0' in e.value.message

def mocked_get_installed_operator_versions_without_release(namespace):
        return (['1.2.0'], [None])

def test_check_for_operator_install_does_not_install_when_operator_is_not_managed_by_helm(mocker):
    # Operator already installed, no release-name annotation found.
    mock_helm_env(mocker)
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json)
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    mocker.patch('kxicli.commands.install.get_installed_operator_versions', mocked_get_installed_operator_versions_without_release)
    assert install.check_for_operator_install('kx-insights', 'insights', '1.2.3', None, True) == (False, False, None, None, [])


def test_check_for_operator_install_errors_when_incompatible_operator_is_not_managed_by_helm(mocker):
    # Operator already installed with a version incompatible with insights, no release-name annotation found.
    mocker.patch('subprocess.run', mocked_helm_search_returns_empty_json)
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    mocker.patch('kxicli.commands.install.get_installed_operator_versions', mocked_get_installed_operator_versions_without_release)
    with pytest.raises(Exception) as e:
        install.check_for_operator_install('kx-insights', 'insights', '1.3.0', None, True)
    assert isinstance(e.value, click.ClickException)
    assert 'Installed kxi-operator version 1.2.0 is incompatible with insights version 1.3.0' in e.value.message

def test_load_values_stores_with_file():
    assert install.load_values_stores(test_val_file) == test_vals

def test_load_values_stores_exception_when_values_file_does_not_exist():
    with pytest.raises(Exception) as e:
        install.load_values_stores('a-non-existant-file')
    assert isinstance(e.value, click.ClickException)
    assert 'File not found: a-non-existant-file. Exiting' in e.value.message


def test_load_values_stores_exception_when_invalid_values_file_provided():
    with temp_file(file_name='new_file') as new_file:
        with open(new_file, 'w') as f:
            f.write('test: {this is not a yaml')
        with pytest.raises(Exception) as e:
            install.load_values_stores(new_file)
        assert isinstance(e.value, click.ClickException)
        assert f'Invalid values file {new_file}' in e.value.message


def test_check_upgrade_version_allows_upgrade():
    assert install.check_upgrade_version('1.3.3', '1.4.0') == None
    assert install.check_upgrade_version('1.3.3', '1.3.4') == None
    assert install.check_upgrade_version('1.3.3', '2.0.0') == None
    assert install.check_upgrade_version('1.3.3', '1.3.3') == None
    assert install.check_upgrade_version('1.5.0-rc.18', '1.5.0-rc.19') == None
    assert install.check_upgrade_version('1.5.0-rc.18', '1.5.0-rc.18') == None

def test_check_upgrade_version_raises_exception_upon_downgrade():
    with pytest.raises(Exception) as e:
        install.check_upgrade_version('1.4.0', '1.3.3')
    assert isinstance(e.value, click.ClickException)
    assert 'Cannot upgrade from version 1.4.0 to version 1.3.3. Target version must be higher than currently installed version.' in e.value.message
    with pytest.raises(Exception) as e:
        install.check_upgrade_version('1.5.0-rc.18', '1.5.0-rc.17')
    assert isinstance(e.value, click.ClickException)
    assert 'Cannot upgrade from version 1.5.0-rc.18 to version 1.5.0-rc.17. Target version must be higher than currently installed version.' in e.value.message

def test_is_valid_upgrade_version_allows_upgrade(mocker):
    mocker.patch('kxicli.commands.install.get_installed_charts', mocked_installed_chart_json)
    assert install.is_valid_upgrade_version('test_release', test_ns, '1.4.0') == True

def test_is_valid_upgrade_version_when_install_not_found(mocker):
    mocker.patch('kxicli.commands.install.get_installed_charts', lambda *args: [])
    assert install.is_valid_upgrade_version('test_release', test_ns, '1.4.0') == False

def test_is_valid_upgrade_version_raises_exception_upon_downgrade(mocker):
    mocker.patch('kxicli.commands.install.get_installed_charts', mocked_installed_chart_json)
    with pytest.raises(Exception) as e:
        install.is_valid_upgrade_version('test_release', test_ns, '1.0.0')
    assert isinstance(e.value, click.ClickException)
    assert 'Cannot upgrade from version 1.2.1 to version 1.0.0. Target version must be higher than currently installed version.' in e.value.message


def test_check_upgrade_version_allows_upgrade():
    assert install.check_operator_rollback_version('1.3.3', '1.3.0') == None
    assert install.check_operator_rollback_version('1.3.3', '1.3.4') == None
    assert install.check_operator_rollback_version('1.3.3', '1.3.6') == None
    assert install.check_operator_rollback_version('1.3.3', '1.3.3') == None
    assert install.check_operator_rollback_version('1.5.0-rc.18', '1.5.0-rc.19') == None
    assert install.check_operator_rollback_version('1.5.0-rc.18', '1.5.0-rc.18') == None

def test_check_operator_rollback_version_raises_exception_upon_downgrade():
    with pytest.raises(Exception) as e:
        install.check_operator_rollback_version('1.4.0', '1.3.3')
    assert isinstance(e.value, click.ClickException)
    assert 'Insights rollback target version 1.4.0 is incompatible with target operator version 1.3.3. Minor versions must match.' in e.value.message
    with pytest.raises(Exception) as e:
        install.check_operator_rollback_version('1.5.0-rc.18', '1.4.0-rc.17')
    assert isinstance(e.value, click.ClickException)
    assert 'Insights rollback target version 1.5.0-rc.18 is incompatible with target operator version 1.4.0-rc.17. Minor versions must match.' in e.value.message

def test_get_values_and_secrets_from_helm_values_exist(mocker):
    mocker.patch('kxicli.commands.install.helm_repo_list', lambda: mocked_helm_repo_list(test_chart_repo_name, test_chart_repo_url))
    mocker.patch('kxicli.commands.install.helm.repo_update')
    test_val_data_updated = copy.deepcopy(test_vals)
    test_lic_secret = 'license-from-helm-values'
    test_val_data_updated['global']['license']['secretName'] = test_lic_secret
    mock_helm_get_values(mocker, test_val_data_updated)
    mock_validate_secret(mocker, True)
    mocker.patch('click.get_current_context')
    assert install.get_values_and_secrets(None,
                                          test_ns,
                                          'test_release',
                                          test_chart_repo_name,
                                          test_chart_repo_url,
                                          None,
                                          None
                                          ) == (None, test_ns, test_chart_repo_name, 'kxi-nexus-pull-secret', test_lic_secret)

def test_get_values_and_secrets_from_helm_values_dont_exist(mocker, capfd):
    mocker.patch('kxicli.commands.install.helm_repo_list', lambda: mocked_helm_repo_list(test_chart_repo_name, test_chart_repo_url))
    mocker.patch('kxicli.commands.install.helm.repo_update')
    test_val_data_updated = copy.deepcopy(test_vals)
    test_lic_secret = 'license-from-helm-values'
    test_val_data_updated['global']['license']['secretName'] = test_lic_secret
    mock_helm_get_values(mocker, test_val_data_updated)
    mock_validate_secret(mocker, False)
    mocker.patch('click.get_current_context')
    with pytest.raises(click.ClickException) as e:
        install.get_values_and_secrets(None,
                                          test_ns,
                                          'test_release',
                                          test_chart_repo_name,
                                          test_chart_repo_url,
                                          None,
                                          None
                                          )
    assert isinstance(e.value, click.ClickException)
    assert e.value.message == 'Validation failed, run "kxi install setup" to fix'
    out, _ = capfd.readouterr()
    assert out == f"""Validating values...
error=Required secret {test_lic_secret} does not exist
error=Required secret kxi-certificate does not exist
error=Required secret kxi-nexus-pull-secret does not exist
error=Required secret kxi-keycloak does not exist
error=Required secret kxi-postgresql does not exist
""" 

def test_get_values_and_secrets_from_helm_values_exist_called_from_azure(mocker):
    test_val_data_updated = copy.deepcopy(test_vals)
    test_val_data_updated['global']['image']['repository'] = 'test-repo.com'
    mock_helm_get_values(mocker, test_val_data_updated)
    mock_validate_secret(mocker, True)
    ctx_mock = mocker.patch('click.get_current_context')
    ctx_mock.return_value.parent.info_name = 'azure'
    assert install.get_values_and_secrets(None,
                                          test_ns,
                                          'test_release',
                                          test_chart_repo_name,
                                          None,
                                          None,
                                          None
                                          ) == (None, test_ns, 'oci://test-repo.com', 'kxi-nexus-pull-secret', 'kxi-license')
