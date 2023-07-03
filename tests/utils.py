import base64
import json
import shutil
from typing import Callable
from unittest.mock import MagicMock
import yaml
from contextlib import contextmanager
from pathlib import Path
import pyk8s
from tempfile import mkdtemp
import subprocess
import const

test_secret_type = 'Opaque'
test_secret_key = 'secret_key'
test_secret_data = {test_secret_key: 'c2VjcmV0X3ZhbHVl'}
test_val_file = str(Path(__file__).parent / 'files' / 'test-values.yaml')
test_asm_backup =  str(Path(__file__).parent / 'files' / 'test-assembly-backup.yaml')

with open(test_val_file, 'r') as f:
    test_val_data = yaml.safe_load(f.read())

test_helm_repo_cache = str(Path(__file__).parent / 'files' / 'helm')
fake_docker_config: dict = {
    'asdf': 'asdf'
}
fake_docker_config_yaml: str = yaml.dump(fake_docker_config)
fake_docker_config_secret: pyk8s.models.V1Secret = pyk8s.models.V1Secret(
    data={
        '.dockerconfigjson': base64.b64encode(fake_docker_config_yaml.encode('ascii')).decode()
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
    raise pyk8s.exceptions.NotFoundError(MagicMock(status=404, reason=None, headers=None, body=None))

def raise_conflict(*args, **kwargs):
    """Helper function to test try/except blocks"""
    raise pyk8s.exceptions.ConflictError(MagicMock(status=409, reason=None, headers=None, body=None))

def return_empty(*args, **kwargs):
    return []

def return_none(*args, **kwargs):
    return None

def return_true(*args, **kwargs):
    return True

def return_false(*args, **kwargs):
    return False

def return_V1status(*args, **kwargs):
    return pyk8s.models.V1Status()

def namespace():
    # tests assume you're running with an active context that has a namespace set
    namespace = 'test'
    try:
        return pyk8s.cl.config.namespace or namespace
    except Exception:
        return namespace


def fake_secret(namespace, name, type="Opaque", keys=(), data={}):
    return pyk8s.models.V1Secret(
        apiVersion="v1",
        metadata=pyk8s.models.V1ObjectMeta(namespace=namespace, name=name),
        type=type, data=data, _required_keys=keys)


def mocked_create_namespaced_secret(namespace=None, body={}):
    obj = pyk8s.models.V1Secret.parse_obj(body)
    obj.metadata.namespace = namespace
    return obj


def mocked_read_namespaced_secret(namespace=None, name=""):
    return pyk8s.models.V1Secret.parse_obj(
        {   
            "metadata": {"namespace": namespace, "name": name}, 
            "data": test_secret_data})


def mocked_patch_namespaced_secret(name, namespace=None, body=None):
    obj = pyk8s.models.V1Secret.parse_obj(body)
    if namespace:
        obj.metadata.namespace = namespace
    obj.metadata.name = name
    return obj

def mocked_create_custom_resource_definition(body):
    return pyk8s.models.V1CustomResourceDefinition.parse_obj(body)

def get_crd_body(name):
    return pyk8s.models.V1CustomResourceDefinition(
        metadata=pyk8s.models.V1ObjectMeta(
            name=name,
            resourceVersion='1'
        ))

def mocked_read_custom_resource_definition(name=None, **kwargs):
    # resource version must be set because 'replace_crd'
    # depends on accessing it
    if name:
        return get_crd_body(name)
    else:
        return pyk8s.resource_item.ItemList([get_crd_body("name")], metadata={})

def mocked_replace_custom_resource_definition(name, body):
    return pyk8s.models.V1CustomResourceDefinition.parse_obj(body)

def mock_kube_secret_api(k8s: MagicMock,
                         create: Callable = mocked_create_namespaced_secret,
                         read: Callable = return_none,
                         patch: Callable = mocked_patch_namespaced_secret):
    k8s.secrets.create = create
    if read != raise_not_found:
        k8s.secrets.get = read
    else:
        k8s.secrets.get = return_none
    k8s.secrets.read = read
    k8s.secrets.patch = patch

def mock_kube_crd_api(
    k8s: MagicMock,
    create: Callable = mocked_create_custom_resource_definition,
    read: Callable = mocked_read_custom_resource_definition,
    replace: Callable = mocked_replace_custom_resource_definition,
    delete: Callable = return_V1status
):
    k8s.customresourcedefinitions.create.side_effect = create
    k8s.customresourcedefinitions.get.side_effect = read
    k8s.customresourcedefinitions.replace.side_effect = replace
    k8s.customresourcedefinitions.delete.side_effect = delete
    return k8s.customresourcedefinitions

def mocked_kube_deployment_list(namespace, **kwargs):
    return [pyk8s.models.V1Deployment(
            metadata=pyk8s.models.V1ObjectMeta(
                name='kxi-operator',
                namespace=namespace,
                labels={"helm.sh/chart":'kxi-operator-1.2.3', "app.kubernetes.io/instance": 'test-helm-name'}
            )
        )]

def mock_kube_deployment_api(
    k8s: MagicMock,
    read: Callable = return_empty,
):
    k8s.deployments.get = read
    k8s.deployments.read = read

def mock_validate_secret(mocker, exists=True, is_valid=True, missing_keys=[]):
    mock = mocker.patch.object(pyk8s.models.V1Secret, 'validate_keys')
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


def mock_helm_repo_list(mocker, name='kx-insights', url=const.test_chart_repo_url):
    mocker.patch('kxicli.resources.helm.repo_list', return_value=[{'name': name, 'url': url}])

def mocked_helm_history_rollback(release, output, show_operator,current_operator_version, current_operator_release):
        res1 =[{"release": release, "revision": 1, "chart": "insights-1.2.3", "app_version":"1.2.3", "status": "deployed"}, {"release": release, "revision": 2, "chart": "insights-1.4.0", "app_version": "1.4.0", "status": "uninstalled"}]
        res2 =[{"release": release, "revision": 1, "chart": "kxi-operator-1.2.3", "app_version": "1.2.3", "status": "uninstalled"},{"release": release, "revision": 2, "chart": "kxi-operator-1.4.0", "app_version": "1.4.0", "status": "uninstalled"}]
        return res1,res2

def mocked_helm_history_rollback_broken(release, output, show_operator,current_operator_version, current_operator_release):
        res1 =[{"release": release, "revision": 1, "chart": "insights-2.2.3", "app_version":"2.2.3", "status": "deployed"}, {"release": release, "revision": 2, "chart": "insights-1.4.0", "app_version": "1.4.0", "status": "uninstalled"}]
        res2 =[{"release": release, "revision": 1, "chart": "kxi-operator-2.2.3", "app_version": "2.2.3", "status": "uninstalled"},{"release": release, "revision": 2, "chart": "kxi-operator-1.4.0", "app_version": "1.4.0", "status": "uninstalled"}]
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