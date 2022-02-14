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
