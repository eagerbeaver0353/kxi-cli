"""This install test is meant to unit test the individual functions in the install command"""
import base64
import copy
import io
import json
import kubernetes as k8s
import os
import pytest
import subprocess
import yaml
import click

from kxicli import common
from kxicli.commands import install
from kxicli.resources import secret
from utils import IPATH_KUBE_COREV1API, temp_file, test_secret_data, test_secret_type, test_secret_key, \
    mock_kube_deployment_api, mocked_kube_deployment_list, mock_kube_secret_api, mocked_read_namespaced_secret, \
    raise_conflict, raise_not_found, test_val_file, mock_validate_secret, mock_helm_env, mocked_helm_repo_list, \
    mock_kube_crd_api, get_crd_body, return_true, return_false, return_V1SecretList
from test_install_e2e import mocked_read_namespaced_secret_return_values, test_vals
from const import test_user, test_pass, test_lic_file, test_chart_repo_name, test_chart_repo_url

# Common test parameters
test_ns = 'test-ns'
test_repo = 'test.kx.com'
test_secret = 'test-secret'
test_key = install.gen_private_key()
test_cert = install.gen_cert(test_key)

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
        stdout='[{"name":"kx-insights/kxi-operator","version":"1.1.0","app_version":"1.1.0-rc.43","description":"KX Insights Operator"}]\n'
    )


def mocked_helm_search_returns_empty_json(base_command, check=True, capture_output=True, text=True):
    return install.subprocess.CompletedProcess(
        args=base_command,
        returncode=0,
        stdout='[]\n'
    )


def mocked_delete_secret(name, namespace):
    global deleted_secret
    deleted_secret = name
    return k8s.client.V1Status()


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


def test_get_install_config_secret_returns_decoded_secret(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)

    s = secret.Secret(test_ns, test_secret)
    res = install.get_install_config_secret(s)

    assert res == yaml.dump(test_vals)


def test_get_install_config_secret_when_does_not_exist(mocker):
    mock_kube_secret_api(mocker)
    s = secret.Secret(test_ns, test_secret)
    res = install.get_install_config_secret(s)

    assert res == None


def test_patch_secret_returns_updated_k8s_secret(mocker):
    mock_kube_secret_api(mocker)
    s = secret.Secret(test_ns, test_secret, test_secret_type)
    s.data = {"secret_key": "new_value"}
    res = s.patch()

    assert res.type == test_secret_type
    assert res.metadata.name == test_secret
    assert res.data == s.data


def test_create_install_config_secret_when_does_not_exists(mocker):
    mock_kube_secret_api(mocker)

    s = secret.Secret(test_ns, test_secret, install.SECRET_TYPE_OPAQUE, install.INSTALL_CONFIG_KEYS)
    s = install.create_install_config(s, test_vals)
    res = s.get_body()

    assert res.type == test_secret_type
    assert res.metadata.name == test_secret
    assert 'values.yaml' in res.data
    assert yaml.full_load(base64.b64decode(res.data['values.yaml'])) == test_vals


def test_create_install_config_secret_when_secret_exists_and_user_overwrites(mocker,monkeypatch):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)

    # Create new values to write to secret
    new_values = {"secretName": "a_test_secret_name"}

    # patch stdin to 'y' for the prompt confirming to overwrite the secret
    monkeypatch.setattr(SYS_STDIN, io.StringIO('y'))
    s = secret.Secret(test_ns, test_secret, install.SECRET_TYPE_OPAQUE, install.INSTALL_CONFIG_KEYS)
    install.create_install_config(s, new_values)
    res = s.get_body()

    assert res.type == test_secret_type
    assert res.metadata.name == test_secret
    assert 'values.yaml' in res.data
    # assert that secret is updated with new_values
    assert yaml.full_load(base64.b64decode(res.data['values.yaml'])) == new_values


def test_create_install_config_secret_when_secret_exists_and_user_declines_overwrite(mocker, monkeypatch):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)

    # update contents of values to write to secret
    new_values = {"secretName": "a_test_secret_name"}

    # patch stdin to 'n' for the prompt, declining to overwrite the secret
    monkeypatch.setattr(SYS_STDIN, io.StringIO('n'))
    s = secret.Secret(test_ns, test_secret, install.SECRET_TYPE_OPAQUE, install.INSTALL_CONFIG_KEYS)
    s = install.create_install_config(s, new_values)
    res = s.read()

    assert res.type == test_secret_type
    assert res.metadata.name == test_secret
    assert 'values.yaml' in res.data
    # assert that secret is unchanged
    assert yaml.full_load(base64.b64decode(res.data['values.yaml'])) == test_vals


def test_build_install_secret():
    data = {"secretName": "a_test_secret_name"}
    s = secret.Secret(test_ns, test_secret, install.SECRET_TYPE_OPAQUE, install.INSTALL_CONFIG_KEYS)
    s = install.populate_install_secret(s, {'values': data})
    res = s.get_body().data

    assert 'values.yaml' in res
    assert yaml.full_load(base64.b64decode(res['values.yaml'])) == data


def test_get_install_values_returns_values_from_secret(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)
    print(install.get_install_values(secret.Secret(test_ns, test_secret)))

    assert install.get_install_values(secret.Secret(test_ns, test_secret)) == yaml.dump(test_vals)
    assert install.get_install_values(secret.Secret(test_ns, None)) is None


def test_get_install_values_exits_when_secret_not_found(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.read_namespaced_secret.side_effect = raise_not_found
    with pytest.raises(Exception) as e:
        install.get_install_values(secret.Secret(test_ns, test_secret))
    assert isinstance(e.value, click.ClickException)
    assert f'Cannot find values secret {test_secret}. Exiting Install\n' in e.value.message


def test_get_operator_version_returns_operator_version_if_passed_regardless_of_rc():
    non_rc = install.get_operator_version('kxi-insights', '1.2.3', '4.5.6')
    rc = install.get_operator_version('kxi-insights', '1.2.3-rc.1', '4.5.6')

    assert non_rc == '4.5.6'
    assert rc == '4.5.6'

def get_minor_version_returns_minor_version_from_semver():
    assert install.get_minor_version('1.0.0') == '1.0'
    assert install.get_minor_version('1.2.3') == '1.2'
    assert install.get_minor_version('1.2.3-rc.50') == '1.2'


def test_get_operator_version_returns_latest_minor_version(mocker):
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json)
    assert install.get_operator_version('kxi-insights', '1.1.1', None) == '1.1.0'


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


def test_operator_installed_returns_true_when_already_exists(mocker):
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    assert install.operator_installed('kx-operator') == True


def test_operator_installed_returns_false_when_does_not_exist(mocker):
    mock_kube_deployment_api(mocker)
    assert install.operator_installed('kx-operator') == False


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
    assert install.get_image_and_license_secret_from_values(None, None, None, None) == (
    'kxi-nexus-pull-secret', 'kxi-license')


def test_get_image_and_license_secret_from_values_returns_from_secret():
    test_vals_secret = copy.deepcopy(test_vals)
    test_vals_secret['global']['imagePullSecrets'] = [{'name': 'image-pull-from-secret'}]
    test_vals_secret['global']['license']['secretName'] = 'license-from-secret'
    assert install.get_image_and_license_secret_from_values(str(test_vals_secret), None, None, None) == (
    'image-pull-from-secret', 'license-from-secret')


def test_get_image_and_license_secret_from_values_file_overrides_secret():
    test_vals_secret = copy.deepcopy(test_vals)
    test_vals_secret['global']['imagePullSecrets'] = [{'name': 'image-pull-from-secret'}]
    test_vals_secret['global']['license']['secretName'] = 'license-from-secret'
    assert install.get_image_and_license_secret_from_values(str(test_vals_secret), test_val_file, None, None) == (
    'kxi-nexus-pull-secret', 'kxi-license')


def test_get_image_and_license_secret_from_values_args_overrides_secret_and_file():
    test_vals_secret = copy.deepcopy(test_vals)
    test_vals_secret['global']['imagePullSecrets'] = [{'name': 'image-pull-from-secret'}]
    test_vals_secret['global']['license']['secretName'] = 'license-from-secret'
    assert install.get_image_and_license_secret_from_values(str(test_vals_secret), test_val_file, 'image-pull-from-arg',
                                                            'license-from-arg') == (
           'image-pull-from-arg', 'license-from-arg')


def test_get_image_and_license_secret_returns_error_when_invalid_secret_passed():
    with pytest.raises(Exception) as e:
        install.get_image_and_license_secret_from_values(test_lic_file, None, None, None)
    assert isinstance(e.value, click.ClickException)
    assert 'Invalid values secret' in e.value.message


def test_get_image_and_license_secret_returns_error_when_invalid_file_passed():
    with pytest.raises(Exception) as e:
        install.get_image_and_license_secret_from_values(None, test_lic_file, None, None)
    assert isinstance(e.value, click.ClickException)
    assert f'Invalid values file' in e.value.message


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


def test_check_for_operator_install_returns_version_to_install(mocker):
    # Operator not already installed, compatible version avaliable on repo
    mock_helm_env(mocker)
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json)
    mock_kube_deployment_api(mocker)
    assert install.check_for_operator_install('kx-insights', 'insights', '1.1.3', None, True) == (True, False, '1.1.0', 'kx-insights', [])


def test_check_for_operator_install_errors_when_operator_repo_charts_not_compatible(mocker):
    # Operator not already installed, no compatible version avaliable on repo. Error returned
    mock_helm_env(mocker)
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json)
    mock_kube_deployment_api(mocker)
    with pytest.raises(Exception) as e:
        install.check_for_operator_install('kx-insights', 'insights', '1.3.0', None, True)
    assert isinstance(e.value, click.ClickException)
    assert 'Compatible version of operator not found' in e.value.message


def test_check_for_operator_install_does_not_install_when_no_repo_charts_available(mocker):
    # Operator already installed, no compatible version avaliable on repo
    mocker.patch('subprocess.run', mocked_helm_search_returns_empty_json)
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    assert install.check_for_operator_install('kx-insights', 'insights', '1.2.3', None, True) == (False, True, None, 'test-helm-name', [])


def test_check_for_operator_install_errors_when_installed_operator_not_compitible(mocker):
    # Incompatiable operator already installed, no version avaliable on repo. Error returned
    mocker.patch('subprocess.run', mocked_helm_search_returns_empty_json)
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    with pytest.raises(Exception) as e:
        install.check_for_operator_install('kx-insights', 'insights', '1.3.0', None, True)
    assert isinstance(e.value, click.ClickException)
    assert 'Compatible version of operator not found' in e.value.message


def test_check_for_operator_install_when_installed_and_available_operators_not_compitible(mocker):
    # Incompatiable operator already installed, no compatible version avaliable on repo. Error returned    
    mock_helm_env(mocker)
    mocker.patch('subprocess.run', mocked_helm_search_returns_valid_json)
    mock_kube_deployment_api(mocker, read=mocked_kube_deployment_list)
    with pytest.raises(Exception) as e:
        install.check_for_operator_install('kx-insights', 'insights', '1.3.0', None, True)
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


def test_upgrade_exception_when_filepath_or_install_secret_not_provided(mocker):
    mocker.patch('kxicli.commands.install.helm_repo_list', lambda: mocked_helm_repo_list(test_chart_repo_name, test_chart_repo_url))
    with pytest.raises(Exception) as e:
        install.perform_upgrade(test_ns, test_repo, test_chart_repo_name, 'test-asm-backup.yaml', '1.3.0', 
                                   '1.3.0', image_pull_secret=None, license_secret=None, install_config_secret=None,
                                   filepath=None, force=False, import_users=None)
    assert isinstance(e.value, click.ClickException)
    assert 'At least one of --install-config-secret and --filepath options must be provided' in e.value.message


def test_load_values_stores_exception_when_values_file_does_not_exist():
    with pytest.raises(Exception) as e:
        install.load_values_stores(test_secret, 'a-non-existant-file')
    assert isinstance(e.value, click.ClickException)
    assert 'File not found: a-non-existant-file. Exiting' in e.value.message


def test_load_values_stores_exception_when_invalid_values_file_provided():
    with temp_file(file_name='new_file') as new_file:
        with open(new_file, 'w') as f:
            f.write('test: {this is not a yaml')
        with pytest.raises(Exception) as e:
            install.load_values_stores(test_secret, new_file)
        assert isinstance(e.value, click.ClickException)
        assert f'Invalid values file {new_file}' in e.value.message


def test_check_supported_crd_api_when_all_apis_supported(mocker):
    mock_kube_crd_api(mocker)
    new_crd_body = get_crd_body('test')
    assert install.check_supported_crd_api(new_crd_body.to_dict())


def test_check_supported_crd_api_when_crd_no_already_installed(mocker):
    mock_kube_crd_api(mocker, read=raise_not_found)
    new_crd_body = get_crd_body('test')
    assert install.check_supported_crd_api(new_crd_body.to_dict())


def test_check_supported_crd_api_when_new_crd_does_not_have_version_in_existing(mocker):
    mock_kube_crd_api(mocker)
    new_crd_body = k8s.client.V1CustomResourceDefinition(
        metadata=k8s.client.V1ObjectMeta(
            name='test',
            resource_version='1'
        ),
        spec=k8s.client.V1CustomResourceDefinitionSpec(
            group='insights.kx.com', 
            scope='Namespaced',
            names=['test'],
            versions=[
                 k8s.client.V1CustomResourceDefinitionVersion(
                    served=True,
                    storage=True,
                    name='v1alpha1'
                    ),
            ]
        )
    )
    assert not install.check_supported_crd_api(new_crd_body.to_dict())


def test_check_supported_crd_apis_returns_false_when_api_versions_match(mocker):
    mocker.patch('kxicli.commands.install.check_supported_crd_api', return_true)
    crd_data = [get_crd_body('test').to_dict(),get_crd_body('test1').to_dict()]
    assert not install.check_supported_crd_apis(crd_data)


def test_delete_helm_secret(mocker):
    mocker.patch('kxicli.commands.install.check_supported_crd_api', return_false)
    mock_kube_secret_api(
        mocker,
        list=lambda **kwargs: return_V1SecretList(
            items=[
                mocked_read_namespaced_secret(test_ns,'helm-release.v1'), 
                mocked_read_namespaced_secret(test_ns,'helm-release.v2')
                ]
            ),
        read=mocked_read_namespaced_secret,
        delete=mocked_delete_secret
    )
    helm_backup_filepath = install.delete_helm_secret('insights', test_ns, None)
    assert os.path.exists(helm_backup_filepath)
    assert deleted_secret == 'helm-release.v2'
    os.remove(helm_backup_filepath)
