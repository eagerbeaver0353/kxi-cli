import base64
import json
import shutil
import yaml
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp
import kubernetes as k8s
from kxicli.resources import secret
import subprocess

test_secret_type = 'Opaque'
test_secret_key = 'secret_key'
test_secret_data = {test_secret_key: 'c2VjcmV0X3ZhbHVl'}
test_val_file = str(Path(__file__).parent / 'files' / 'test-values.yaml')

with open(test_val_file, 'r') as f:
    test_val_data = yaml.safe_load(f.read())

test_helm_repo_cache = str(Path(__file__).parent / 'files' / 'helm')
fake_docker_config: dict = {
    'asdf': 'asdf'
}
fake_docker_config_yaml: str = yaml.dump(fake_docker_config)
fake_docker_config_secret: k8s.client.V1Secret = k8s.client.V1Secret(
    data={
        '.dockerconfigjson': base64.b64encode(fake_docker_config_yaml.encode('ascii'))
    }
)
test_asm_file = str(Path(__file__).parent / 'files' / 'assembly-v1.yaml')
test_asm_file2 = str(Path(__file__).parent / 'files' / 'assembly2-v1.yaml')

IPATH_KUBE_COREV1API = 'kubernetes.client.CoreV1Api'
IPATH_KUBE_APIEXTENSTIONSV1API = 'kubernetes.client.ApiextensionsV1Api'
IPATH_KUBE_APPSV1API = 'kubernetes.client.AppsV1Api'
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

def return_V1status(*args, **kwargs):
    return k8s.client.V1Status()

def namespace():
    # tests assume you're running with an active context that has a namespace set
    try:
        return k8s.config.list_kube_config_contexts()[1]['context']['namespace']
    except (TypeError, k8s.config.config_exception.ConfigException):
        return 'test'

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
    replace=mocked_replace_custom_resource_definition,
    delete=return_V1status
):
    mock = mocker.patch(IPATH_KUBE_APIEXTENSTIONSV1API)
    mock.return_value.create_custom_resource_definition = create
    mock.return_value.read_custom_resource_definition = read
    mock.return_value.replace_custom_resource_definition = replace
    mock.return_value.delete_custom_resource_definition = delete
    return mock

def mock_list_empty_deployment_api(namespace, **kwargs):
    return k8s.client.V1DeploymentList(items={})

def mocked_kube_deployment_list(namespace, **kwargs):
    return k8s.client.V1DeploymentList(
        items=[k8s.client.V1Deployment(
            metadata=k8s.client.V1ObjectMeta(
                name='kxi-operator',
                namespace=namespace,
                labels={"helm.sh/chart":'kxi-operator-1.2.3', "app.kubernetes.io/instance": 'test-helm-name'}
            )
        )]
    )

def mock_kube_deployment_api(
    mocker,
    read=mock_list_empty_deployment_api,
):
    mock = mocker.patch(IPATH_KUBE_APPSV1API)
    mock.return_value.list_namespaced_deployment = read

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

def mock_helm_get_values(mocker, data, throw_exception=False, exception_msg='Get values failed'):
    def helm_get_values(*args):
        if throw_exception:
            raise subprocess.CalledProcessError(1, ['helm', 'get', 'values'], stderr=exception_msg)
        return data
    mocker.patch('kxicli.resources.helm.get_values', helm_get_values)

def mock_config_exception():
    raise k8s.config.config_exception.ConfigException('Invalid kube-config file. No configuration found.')

def mock_incluster_config_exception():
    raise k8s.config.config_exception.ConfigException('Service host/port is not set.')

def mock_load_kube_config(mocker):
    CUSTOM_OBJECT_API = 'kubernetes.config.load_kube_config'
    mocker.patch(CUSTOM_OBJECT_API, mock_config_exception)

def mock_load_kube_config_incluster(mocker):
    CUSTOM_OBJECT_API = 'kubernetes.config.load_incluster_config'
    mocker.patch(CUSTOM_OBJECT_API, mock_incluster_config_exception)

def mock_list_kube_config_contexts(mocker):
    CUSTOM_OBJECT_API = 'kubernetes.config.list_kube_config_contexts'
    mocker.patch(CUSTOM_OBJECT_API, mock_config_exception)

def mocked_helm_repo_list(name, url):
    return [{'name': name, 'url': url}]

def mocked_helm_history_rollback(release, output, show_operator,current_operator_version, current_operator_release):
        res1 =[{"release": release, "revision": 1, "chart": "insights-1.2.3", "app_version":"1.2.3", "status": "deployed"}, {"release": release, "revision": 2, "chart": "insights-1.4.0", "app_version": "1.4.0", "status": "uninstalled"}]
        res2 =[{"release": release, "revision": 1, "chart": "kxi-operator-1.2.3", "app_version": "1.2.3", "status": "uninstalled"},{"release": release, "revision": 2, "chart": "kxi-operator-1.4.0", "app_version": "1.4.0", "status": "uninstalled"}]
        return res1,res2

def mocked_helm_history_rollback_same_operator(release, output, show_operator, current_operator_version, current_operator_release):
        res1 =[{"release": release, "revision": 1, "chart": "insights-1.4.1", "app_version":"1.4.1", "status": "deployed"}, {"release": release, "revision": 2, "chart": "insights-1.4.0", "app_version": "1.4.0", "status": "uninstalled"}]
        res2 =[{"release": release, "revision": 1, "chart": "kxi-operator-1.4.1", "app_version": "1.4.1", "status": "uninstalled"},{"release": release, "revision": 2, "chart": "kxi-operator-1.4.0", "app_version": "1.4.0", "status": "uninstalled"}]
        return res1,res2

def get_assembly_name(file_path: str):
   with open(file_path, "r") as file:
    yaml_data = yaml.safe_load(file)

    # extract the value of metadata.name
    name = yaml_data["metadata"]["name"]
    return name