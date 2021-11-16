"""This install test is meant to unit test the inidividal functions in the install command"""
import os
import base64
import kubernetes as k8s
from kxi.commands import install

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
    mocker.patch('kxi.commands.install.create_secret', mocked_create_secret)
    test_cfg = install.create_docker_config(test_repo, test_user, test_pass)
    res = install.create_docker_config_secret(test_ns, test_secret, test_cfg)

    assert res.type == 'kubernetes.io/dockerconfigjson'
    assert res.metadata.name == test_secret
    assert '.dockerconfigjson' in res.data

def test_create_license_secret(mocker):
    mocker.patch('kxi.commands.install.create_secret', mocked_create_secret)
    res = install.create_license_secret(test_ns, test_secret, test_lic_file)

    assert res.type == 'Opaque'
    assert res.metadata.name == test_secret
    assert 'license' in res.string_data

def test_create_tls_secret(mocker):
    mocker.patch('kxi.commands.install.create_secret', mocked_create_secret)
    res = install.create_tls_secret(test_ns, test_secret, test_cert, test_key)

    assert res.type == 'kubernetes.io/tls'
    assert res.metadata.name == test_secret
    assert 'tls.crt' in res.data
    assert 'tls.key' in res.data

