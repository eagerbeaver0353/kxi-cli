import shutil
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp
import kubernetes as k8s
from kxicli.resources import secret

test_secret_type = 'Opaque'
test_secret_key = 'secret_key'
test_secret_data = {test_secret_key: 'secret_value'}
test_val_file = str(Path(__file__).parent / 'files' / 'test-values.yaml')

IPATH_KUBE_COREV1API = 'kubernetes.client.CoreV1Api'

@contextmanager
def temp_file(file_name: str, prefix: str = 'kxicli-'):
    dir_name: str = str()
    inited: bool = False
    try:
        dir_name = mkdtemp(prefix=prefix)
        inited = True
        temp_file_name = str(Path(dir_name).joinpath(file_name))
        yield temp_file_name
    finally:
        if inited:
            shutil.rmtree(dir_name)


def raise_not_found(*args, **kwargs):
    """Helper function to test try/except blocks"""
    raise k8s.client.rest.ApiException(status=404)


def return_none(**kwargs):
    return None

def mocked_create_namespaced_secret(namespace, body):
    return secret.Secret(namespace, body.metadata.name, body.type, data=body.data, string_data=body.string_data).get_body()


def mocked_read_namespaced_secret(namespace, name):
    return secret.Secret(namespace, name, test_secret_type, data=test_secret_data).get_body()


def mocked_patch_namespaced_secret(name, namespace, body):
    return secret.Secret(namespace, name, body.type, data=body.data).get_body()


def mock_kube_secret_api(mocker, create=mocked_create_namespaced_secret, read=return_none, patch=mocked_patch_namespaced_secret):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.create_namespaced_secret = create
    mock.return_value.read_namespaced_secret = read
    mock.return_value.patch_namespaced_secret = patch

def mock_validate_secret(mocker, exists=True, is_valid=True, missing_keys=[]):
    mock = mocker.patch.object(secret.Secret, 'validate')
    mock.return_value = (exists, is_valid, missing_keys)
