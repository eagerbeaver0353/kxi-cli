"""This install test is meant to unit test the inidividal functions in the install command"""
import io
import os
import base64
import kubernetes as k8s
from kxicli.commands import install

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

# This is used to mock the main function that makes calls to the control plane
def mocked_create_secret(namespace, name, secret_type, data=None, string_data=None):
    print('Running mocked create_secret function')
    return install.get_secret_body(name, secret_type, data, string_data)

# These are used to mock helm calls to list deployed releases
# helm list --filter insights --deployed -o json
def mocked_helm_list_returns_valid_json(base_command):
    return '[{"name":"insights","namespace":"testnamespace","revision":"1","updated":"2022-02-23 10:39:53.7668809 +0000 UTC","status":"deployed","chart":"insights-0.11.0-rc.39","app_version":"0.11.0-rc.8"}]'

def mocked_helm_list_returns_empty_json(base_command):
    return '[]'

def mocked_all_crds_exist(name):
    return True

def mocked_one_crd_exists(name):
    return name == 'testcrd'

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

def test_create_license_secret(mocker):
    mocker.patch('kxicli.commands.install.create_secret', mocked_create_secret)
    res = install.create_license_secret(test_ns, test_secret, test_lic_file)

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert 'license' in res.string_data

def test_create_tls_secret(mocker):
    mocker.patch('kxicli.commands.install.create_secret', mocked_create_secret)
    res = install.create_tls_secret(test_ns, test_secret, test_cert, test_key)

    assert res.type == 'kubernetes.io/tls'
    assert res.metadata.name == test_secret
    assert 'tls.crt' in res.data
    assert 'tls.key' in res.data

def test_get_operator_version_returns_operator_version_if_passed_regardless_of_rc():
    non_rc = install.get_operator_version('1.2.3', '4.5.6')
    rc = install.get_operator_version('1.2.3-rc.1', '4.5.6')

    assert non_rc == '4.5.6'
    assert rc == '4.5.6'

def test_get_operator_version_returns_insights_version_if_not_rc():
    assert install.get_operator_version('1.2.3', None) == '1.2.3'

def test_get_operator_version_returns_prompts_for_operater_version_if_rc(monkeypatch):
    test_version = '0.1.2-rc.2'
    # patch stdin to end the prompt
    monkeypatch.setattr('sys.stdin', io.StringIO(test_version))

    assert install.get_operator_version('1.2.3-rc.1', None) == test_version

def test_insights_installed_returns_true_when_already_exists(mocker):
    mocker.patch('subprocess.check_output', mocked_helm_list_returns_valid_json)
    assert install.insights_installed('insights') == True

def test_insights_installed_returns_false_when_already_exists(mocker):
    mocker.patch('subprocess.check_output', mocked_helm_list_returns_empty_json)
    assert install.insights_installed('insights') == False

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
