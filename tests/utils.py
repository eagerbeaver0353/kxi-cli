import json
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
test_helm_repo_cache = str(Path(__file__).parent / 'files' / 'helm')

IPATH_KUBE_COREV1API = 'kubernetes.client.CoreV1Api'
IPATH_KUBE_APIEXTENSTIONSV1API = 'kubernetes.client.ApiextensionsV1Api'
IPATH_CLICK_PROMPT = 'click.prompt'

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

# Allows us to use Kubernetes deserialization functions for easy testing
class KubeResponse():
    def __init__(self, data):
        self.data = data

def raise_not_found(*args, **kwargs):
    """Helper function to test try/except blocks"""
    raise k8s.client.rest.ApiException(status=404)

def raise_conflict(*args, **kwargs):
    """Helper function to test try/except blocks"""
    raise k8s.client.rest.ApiException(status=409)

def return_none(*args, **kwargs):
    return None

def return_true(*args, **kwargs):
    return True

def return_false(*args, **kwargs):
    return False

def mocked_create_namespaced_secret(namespace, body):
    return secret.Secret(namespace, body.metadata.name, body.type, data=body.data, string_data=body.string_data).get_body()


def mocked_read_namespaced_secret(namespace, name):
    return secret.Secret(namespace, name, test_secret_type, data=test_secret_data).get_body()


def mocked_patch_namespaced_secret(name, namespace, body):
    return secret.Secret(namespace, name, body.type, data=body.data).get_body()

def mocked_create_custom_resource_definition(body):
    data = KubeResponse(json.dumps(body))
    return k8s.client.ApiClient().deserialize(data, 'V1CustomResourceDefinition')

def get_crd_body(name):
    return k8s.client.V1CustomResourceDefinition(
        metadata=k8s.client.V1ObjectMeta(
            name=name,
            resource_version='1'
        ),
        spec={}
        )

def mocked_read_custom_resource_definition(name):
    # resource version must be set because 'replace_crd'
    # depends on accessing it
    return get_crd_body(name)

def mocked_replace_custom_resource_definition(name, body):
    data = KubeResponse(json.dumps(body))
    return k8s.client.ApiClient().deserialize(data, 'V1CustomResourceDefinition')

def mock_kube_secret_api(mocker, create=mocked_create_namespaced_secret, read=return_none, patch=mocked_patch_namespaced_secret):
    mock = mocker.patch(IPATH_KUBE_COREV1API)
    mock.return_value.create_namespaced_secret = create
    mock.return_value.read_namespaced_secret = read
    mock.return_value.patch_namespaced_secret = patch

def mock_kube_crd_api(
    mocker,
    create=mocked_create_custom_resource_definition,
    read=mocked_read_custom_resource_definition,
    replace=mocked_replace_custom_resource_definition
):
    mock = mocker.patch(IPATH_KUBE_APIEXTENSTIONSV1API)
    mock.return_value.create_custom_resource_definition = create
    mock.return_value.read_custom_resource_definition = read
    mock.return_value.replace_custom_resource_definition = replace

def mock_validate_secret(mocker, exists=True, is_valid=True, missing_keys=[]):
    mock = mocker.patch.object(secret.Secret, 'validate')
    mock.return_value = (exists, is_valid, missing_keys)

def mock_helm_env(mocker):
    def helm_env():
        return {
            'HELM_REPOSITORY_CACHE': test_helm_repo_cache
        }
    mocker.patch('kxicli.resources.helm.env', helm_env)

def mock_helm_fetch(mocker):
    def helm_fetch(*args):
        return args
    mocker.patch('kxicli.resources.helm.fetch', helm_fetch)