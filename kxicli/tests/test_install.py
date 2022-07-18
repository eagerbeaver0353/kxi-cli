"""This install test is meant to unit test the individual functions in the install command"""
import pytest
import copy
import io
import os
import base64
import yaml
import kubernetes as k8s
from kxicli.commands import install
from kxicli import common

# Common test parameters

test_ns = 'test-ns'
test_user = 'user'
test_pass = 'password'
test_repo = 'test.kx.com'
test_secret = 'test-secret'
test_secret_type = 'Opaque'
test_key = install.gen_private_key()
test_cert = install.gen_cert(test_key)
test_lic_file = os.path.dirname(__file__) + '/files/test-license'
test_val_file = os.path.dirname(__file__) + '/files/test-values.yaml'
test_kube_config = os.path.dirname(__file__) + '/files/test-kube-config'

common.config.load_config("default")

# Constants for common import paths
IPATH_KUBE_COREV1API = 'kubernetes.client.CoreV1Api'
IPATH_INSTALL_READ_SECRET = 'kxicli.commands.install.read_secret'
IPATH_CLICK_PROMPT = 'click.prompt'


with open(test_val_file, 'rb') as values_file:
    test_vals = yaml.full_load(values_file)

with open(test_kube_config, 'r') as f:    
    k8s_config = yaml.full_load(f)

def raise_not_found(**kwargs):
    """Helper function to test try/except blocks"""
    raise k8s.client.rest.ApiException(status=404)

def return_none(**kwargs):
    return None

# This is used to mock the main function that makes calls to the control plane
def mocked_create_secret(namespace, name, secret_type, data=None, string_data=None):
    print('Running mocked create_secret function')
    return install.get_secret_body(name, secret_type, data, string_data)

# This is used to mock the k8s api function that makes calls to the control plane. Return a hard-coded secret. 
def mocked_read_namespaced_secret(namespace, name):
    return install.get_secret_body(name, 'Opaque', data={"secret_key": "secret_value"})

def mocked_read_namespaced_secret_return_values(namespace, name):
    return install.get_secret_body(name, 'Opaque', data=install.build_install_secret(test_vals))  

def mocked_patch_namespaced_secret(name, namespace, body):
    current_secret = install.get_secret_body(name, 'Opaque', data={"secret_key": "secret_value"})
    current_secret.data.update(body.data)
    return current_secret

# These are used to mock helm calls to list deployed releases
# helm list --filter insights --deployed -o json
def mocked_helm_list_returns_valid_json(base_command):
    return '[{"name":"insights","namespace":"testNamespace","revision":"1","updated":"2022-02-23 10:39:53.7668809 +0000 UTC","status":"deployed","chart":"insights-0.11.0-rc.39","app_version":"0.11.0-rc.8"}]'

def mocked_helm_list_returns_empty_json(base_command):
    return '[]'

def mocked_all_crds_exist(name):
    return True

def mocked_one_crd_exists(name):
    return name == 'testcrd'

def mock_k8s_contexts():
    return ['', k8s_config['contexts'][0]]

def test_get_secret_body_string_data_parameter():
    sdata = {'a':'b'}

    expected = k8s.client.V1Secret()
    expected.metadata = k8s.client.V1ObjectMeta(name=test_secret)
    expected.type = test_secret_type
    expected.string_data = sdata

    secret = install.get_secret_body(test_secret, test_secret_type, string_data=sdata)

    assert secret == expected

def test_get_secret_body_data_parameter():
    data = {'a':'b'}

    expected = k8s.client.V1Secret()
    expected.metadata = k8s.client.V1ObjectMeta(name=test_secret)
    expected.type = test_secret_type
    expected.data = data
    secret = install.get_secret_body(test_secret, test_secret_type, data=data)

    assert secret == expected

def test_create_docker_config():
    test_cfg = {
        'auths': {
            test_repo : {
                'username': test_user,
                'password': test_pass,
                'auth': base64.b64encode(f'{test_user}:{test_pass}'.encode()).decode('ascii')
            }
        }
    }

    assert install.create_docker_config(test_repo, test_user, test_pass) == test_cfg

def test_create_docker_secret(mocker):
    mocker.patch('kxicli.commands.install.create_secret', mocked_create_secret)
    test_cfg = install.create_docker_config(test_repo, test_user, test_pass)
    res = install.create_docker_config_secret(test_ns, test_secret, test_cfg)

    assert res.type == 'kubernetes.io/dockerconfigjson'
    assert res.metadata.name == test_secret
    assert '.dockerconfigjson' in res.data

def test_create_license_secret_encoded(mocker):
    mocker.patch('kxicli.commands.install.create_secret', mocked_create_secret)
    res = install.create_license_secret(test_ns, test_secret, test_lic_file, True)

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert 'license' in res.string_data
    with open(test_lic_file, 'rb') as license_file:
        assert base64.b64decode(res.string_data['license']) == license_file.read()

def test_create_license_secret_decoded(mocker):
    mocker.patch('kxicli.commands.install.create_secret', mocked_create_secret)
    res = install.create_license_secret(test_ns, test_secret, test_lic_file, False)

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert 'license' in res.data
    with open(test_lic_file, 'rb') as license_file:
        assert base64.b64decode(res.data['license']) == license_file.read()

def test_create_tls_secret(mocker):
    mocker.patch('kxicli.commands.install.create_secret', mocked_create_secret)
    res = install.create_tls_secret(test_ns, test_secret, test_cert, test_key)

    assert res.type == 'kubernetes.io/tls'
    assert res.metadata.name == test_secret
    assert 'tls.crt' in res.data
    assert 'tls.key' in res.data

def test_read_secret_returns_k8s_secret(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.read_namespaced_secret = mocked_read_namespaced_secret
    res = install.read_secret(namespace=test_ns, name=test_secret)

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert res.data == {"secret_key": "secret_value"}

def test_read_secret_returns_empty_when_does_not_exist(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.read_namespaced_secret.side_effect = raise_not_found
    res = install.read_secret(namespace=test_ns, name=test_secret)

    assert res == None

def test_get_install_config_secret_returns_decoded_secret(mocker):
    mocker.patch(IPATH_INSTALL_READ_SECRET, mocked_read_namespaced_secret_return_values)
    res = install.get_install_config_secret(test_ns, test_secret)

    assert res == yaml.dump(test_vals)

def test_get_install_config_secret_when_does_not_exist(mocker):
    mocker.patch(IPATH_INSTALL_READ_SECRET, return_none)
    res = install.get_install_config_secret(test_ns, test_secret)

    assert res == None

def test_patch_secret_returns_updated_k8s_secret(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.patch_namespaced_secret = mocked_patch_namespaced_secret
    res = install.patch_secret(namespace=test_ns, name=test_secret, secret_type='Opaque', data={"secret_key": "new_value"})

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert res.data == {"secret_key": "new_value"}

def test_create_install_config_secret_when_does_not_exists(mocker):
    mocker.patch('kxicli.commands.install.create_secret', mocked_create_secret)
    mocker.patch(IPATH_INSTALL_READ_SECRET, return_none)

    res = install.create_install_config_secret(test_ns, test_secret, test_vals)

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert 'values.yaml' in res.data
    assert yaml.full_load(base64.b64decode(res.data['values.yaml'])) == test_vals

def test_create_install_config_secret_when_secret_exists_and_user_overwrites(mocker,monkeypatch):
    mocker.patch('kxicli.commands.install.patch_secret', mocked_create_secret)
    mocker.patch(IPATH_INSTALL_READ_SECRET, mocked_read_namespaced_secret_return_values)

    # Create new values to write to secret
    new_values = {"secretName": "a_test_secret_name"}

    # patch stdin to 'y' for the prompt confirming to overwrite the secret
    monkeypatch.setattr('sys.stdin', io.StringIO('y'))
    res = install.create_install_config_secret(test_ns, test_secret, new_values)

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert 'values.yaml' in res.data
    # assert that secret is updated with new_values
    assert yaml.full_load(base64.b64decode(res.data['values.yaml'])) == new_values

def test_create_install_config_secret_when_secret_exists_and_user_declines_overwrite(mocker,monkeypatch):
    mocker.patch('kxicli.commands.install.patch_secret', mocked_create_secret)
    mocker.patch(IPATH_INSTALL_READ_SECRET, mocked_read_namespaced_secret_return_values)

    # update contents of values to write to secret
    new_values = {"secretName": "a_test_secret_name"}

    # patch stdin to 'n' for the prompt, declining to overwrite the secret
    monkeypatch.setattr('sys.stdin', io.StringIO('n'))
    res = install.create_install_config_secret(test_ns, test_secret, new_values)

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert 'values.yaml' in res.data
    # assert that secret is unchanged
    assert yaml.full_load(base64.b64decode(res.data['values.yaml'])) == test_vals

def test_build_install_secret():
    data = {"secretName": "a_test_secret_name"}
    res = install.build_install_secret(data)

    assert 'values.yaml' in res
    assert yaml.full_load(base64.b64decode(res['values.yaml'])) == data

def test_get_install_values_returns_values_from_secret(mocker):
    mocker.patch(IPATH_INSTALL_READ_SECRET, mocked_read_namespaced_secret_return_values)
    assert install.get_install_values(namespace=test_ns, install_config_secret=test_secret) == yaml.dump(test_vals)
    assert install.get_install_values(namespace=test_ns, install_config_secret=None) == None

def test_get_install_values_exits_when_secret_not_found(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.read_namespaced_secret.side_effect = raise_not_found
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        install.get_install_values(namespace=test_ns, install_config_secret=test_secret)
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1

def test_get_operator_version_returns_operator_version_if_passed_regardless_of_rc():
    non_rc = install.get_operator_version('1.2.3', '4.5.6')
    rc = install.get_operator_version('1.2.3-rc.1', '4.5.6')

    assert non_rc == '4.5.6'
    assert rc == '4.5.6'

def test_get_operator_version_returns_insights_version_if_not_rc():
    assert install.get_operator_version('1.2.3', None) == '1.2.3'

def test_get_operator_version_returns_prompts_for_operator_version_if_rc(monkeypatch):
    test_version = '0.1.2-rc.2'
    # patch stdin to end the prompt
    monkeypatch.setattr('sys.stdin', io.StringIO(test_version))

    assert install.get_operator_version('1.2.3-rc.1', None) == test_version

def test_insights_installed_returns_true_when_already_exists(mocker):
    mocker.patch('subprocess.check_output', mocked_helm_list_returns_valid_json)
    assert install.insights_installed('insights', test_ns) == True

def test_insights_installed_returns_false_when_already_exists(mocker):
    mocker.patch('subprocess.check_output', mocked_helm_list_returns_empty_json)
    assert install.insights_installed('insights', test_ns) == False

def test_operator_installed_returns_true_when_already_exists(mocker):
    mocker.patch('subprocess.check_output', mocked_helm_list_returns_valid_json)
    assert install.operator_installed('insights') == True

def test_operator_installed_returns_false_when_already_exists(mocker):
    mocker.patch('subprocess.check_output', mocked_helm_list_returns_empty_json)
    assert install.operator_installed('insights') == False

def test_get_existing_crds_return_all_crds(mocker):
    mocker.patch('kxicli.common.crd_exists', mocked_all_crds_exist)
    assert install.common.get_existing_crds(['testcrd']) == ['testcrd']
    assert install.common.get_existing_crds(['testcrd', 'testcrd2']) == (['testcrd', 'testcrd2'])
    assert install.common.get_existing_crds(['testcrd', 'testcrd2', 'testcrd3']) == (['testcrd', 'testcrd2', 'testcrd3'])

def test_get_existing_crds_return_existing_crds_only(mocker):
    mocker.patch('kxicli.common.crd_exists', mocked_one_crd_exists)
    assert install.common.get_existing_crds(['testcrd']) == ['testcrd']
    assert install.common.get_existing_crds(['testcrd', 'testcrd2']) == (['testcrd'])
    assert install.common.get_existing_crds(['testcrd', 'testcrd2', 'testcrd3']) == (['testcrd'])

def test_sanitize_auth_url():
    https_replaced = install.sanitize_auth_url('https://keycloak.keycloak.svc.cluster.local/auth/')
    trailing_slash = install.sanitize_auth_url('https://keycloak.keycloak.svc.cluster.local/auth')
    prepend_http = install.sanitize_auth_url('keycloak.keycloak.svc.cluster.local/auth')

    expected = 'http://keycloak.keycloak.svc.cluster.local/auth/'
    assert https_replaced == expected
    assert trailing_slash == expected
    assert prepend_http == expected

def test_get_namespace(mocker):
    mocker.patch('kubernetes.config.list_kube_config_contexts', mock_k8s_contexts)
    
    res = install.get_namespace(None)
    assert res[1] == 'test'
    assert res[0] == k8s_config['contexts'][0]
    assert 'cluster' in res[0]['context'].keys()

def test_get_image_and_license_secret_from_values_returns_defaults():
    assert install.get_image_and_license_secret_from_values(None, None, None, None) == ('kxi-nexus-pull-secret','kxi-license')

def test_get_image_and_license_secret_from_values_returns_from_secret():
    test_vals_secret = copy.deepcopy(test_vals)
    test_vals_secret['global']['imagePullSecrets'] = [{'name': 'image-pull-from-secret'}]
    test_vals_secret['global']['license']['secretName'] = 'license-from-secret'
    assert install.get_image_and_license_secret_from_values(str(test_vals_secret), None, None, None) == ('image-pull-from-secret', 'license-from-secret')

def test_get_image_and_license_secret_from_values_file_overrides_secret():
    test_vals_secret = copy.deepcopy(test_vals)
    test_vals_secret['global']['imagePullSecrets'] = [{'name': 'image-pull-from-secret'}]
    test_vals_secret['global']['license']['secretName'] = 'license-from-secret'
    assert install.get_image_and_license_secret_from_values(str(test_vals_secret), test_val_file, None, None) == ('kxi-nexus-pull-secret','kxi-license')

def test_get_image_and_license_secret_from_values_args_overrides_secret_and_file():
    test_vals_secret = copy.deepcopy(test_vals)
    test_vals_secret['global']['imagePullSecrets'] = [{'name': 'image-pull-from-secret'}]
    test_vals_secret['global']['license']['secretName'] = 'license-from-secret'
    assert install.get_image_and_license_secret_from_values(str(test_vals_secret), test_val_file, 'image-pull-from-arg', 'license-from-arg') == ('image-pull-from-arg', 'license-from-arg')

def test_get_image_and_license_secret_returns_error_when_invalid_secret_passed():
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        install.get_image_and_license_secret_from_values(test_lic_file, None, None, None)
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1

def test_get_image_and_license_secret_returns_error_when_invalid_file_passed():
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        install.get_image_and_license_secret_from_values(None, test_lic_file, None, None)
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1

def test_get_missing_key_with_no_dict_returns_all_keys():
    keys = ('a', 'b')
    assert list(keys) == install.get_missing_keys(None, ('a', 'b'))

def test_get_missing_key_with_key_missing():
    assert ['a'] == install.get_missing_keys({'b': 2, 'c': 3}, ('a', 'b'))

def test_get_missing_key_with_no_key_missing():
    assert [] == install.get_missing_keys({'a': 1, 'b': 2}, ('a', 'b'))

def test_validate_secret_when_no_secret_exists(mocker):
    # return 'None' to indicate that the secret was not found
    mocker.patch(IPATH_INSTALL_READ_SECRET, return_value=None)
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        install.validate_secret(test_ns, test_secret, test_secret_type, ['test'])

    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1

def test_validate_secret_when_missing_a_key(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.read_namespaced_secret = mocked_read_namespaced_secret
    assert (False, ['test']) == install.validate_secret(test_ns, test_secret, test_secret_type, ('test',))

def test_validate_secret_when_incorrect_type(mocker):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.read_namespaced_secret = mocked_read_namespaced_secret
    assert (False, []) == install.validate_secret(test_ns, test_secret, 'kubernetes.io/tls', ('secret_key',))

def test_prompt_and_validate_existing_secret_when_no_validation_defined(mocker):
    mocker.patch(IPATH_CLICK_PROMPT, return_value=test_secret)
    assert test_secret == install.prompt_and_validate_existing_secret(test_ns, 'no_validation')

def test_secret_validation_in_prompt_and_validate_existing_secret_validation_when_valid(mocker):
    # returns a secret that satisfies the validation logic
    # it has the expected type and the required keys based on the secret_use
    def gen_valid_secret(secret_use):
        req_keys = install.SECRET_VALIDATION[secret_use][1]
        secret_data = dict(zip(req_keys, [1]*len(req_keys)))
        return install.get_secret_body(test_secret, install.SECRET_VALIDATION[secret_use][0], data=secret_data)

    mocker.patch(IPATH_CLICK_PROMPT, return_value=test_secret)
    for secret_use in install.SECRET_VALIDATION:
        mocker.patch(IPATH_INSTALL_READ_SECRET, return_value=gen_valid_secret(secret_use))
        assert test_secret == install.prompt_and_validate_existing_secret(test_ns, secret_use)

def test_secret_validation_in_prompt_and_validate_existing_secret_validation_when_invalid(mocker):
    # returns a secret that fails the validation logic
    # it doesn't have all the required keys
    def gen_invalid_secret(secret_use):
        secret_data = {'a': 1}
        return install.get_secret_body(test_secret, install.SECRET_VALIDATION[secret_use][0], data=secret_data)

    mocker.patch(IPATH_CLICK_PROMPT, return_value=test_secret)
    for secret_use in install.SECRET_VALIDATION:
        mocker.patch(IPATH_INSTALL_READ_SECRET, return_value=gen_invalid_secret(secret_use))
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            install.prompt_and_validate_existing_secret(test_ns, secret_use)

        assert pytest_wrapped_e.type == SystemExit
        assert pytest_wrapped_e.value.code == 1
