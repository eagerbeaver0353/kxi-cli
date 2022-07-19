"""This end 2 end test validates the inputs and outputs of the install command directly"""
import copy
import filecmp
import os
import shutil
import yaml
import click
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp

import kubernetes as k8s
from click.testing import CliRunner

from kxicli import common
from kxicli import main

common.config.config_file = os.path.dirname(__file__) + '/files/test-cli-config'
common.config.load_config("default")

test_host = 'test.internal-insights.kx.com'
test_chart_repo_name = 'internal-nexus-dev'
test_chart_repo_url = 'https://nexus.internal-insights.kx.com/repository/kx-helm-charts-dev'
test_image_repo = 'test-repo.internal-insights.kx.com'
test_user = 'user'
test_pass = 'password'
test_auth_url = 'http://keycloak.keycloak.svc.cluster.local/auth/'
test_chart = 'kx-insights/insights'
test_operator_chart = 'kx-insights/kxi-operator'
test_install_secret = 'test-install-secret'

test_val_file = os.path.dirname(__file__) + '/files/test-values.yaml'
test_val_file_shared_keycloak = os.path.dirname(__file__) + '/files/test-values-shared-keycloak.yaml'
test_k8s_config = os.path.dirname(__file__) + '/files/test-kube-config'
test_cli_config_static = os.path.dirname(__file__) + '/files/test-cli-config'
test_lic_file = os.path.dirname(__file__) + '/files/test-license'
expected_test_output_file = str(Path(__file__).parent / 'files' / 'output-values.yaml')
test_output_file_lic_env_var = os.path.dirname(__file__) + '/files/output-values-license-as-env-var.yaml'
test_docker_config_json = os.path.dirname(__file__) + '/files/test-docker-config-json'
test_asm_file = os.path.dirname(__file__) + '/files/assembly-v1.yaml'
test_asm_name = 'basic-assembly' #As per contents of test_asm_file
test_asm_backup = os.path.dirname(__file__) + '/files/test-assembly-backup.yaml'
test_crds = ['assemblies.insights.kx.com','assemblyresources.insights.kx.com']

_, active_context = k8s.config.list_kube_config_contexts()
test_namespace = active_context['context']['namespace']
test_cluster = active_context['context']['cluster']

with open(test_val_file, 'rb') as values_file:
    test_vals = yaml.full_load(values_file)

delete_crd_params = []
insights_installed_flag = True
operator_installed_flag = True
crd_exists_flag = True
running_assembly = {}
copy_secret_params=[]

# override where the command looks for the docker config json
# by default this is $HOME/.docker/config.json
main.install.docker_config_file_path = test_docker_config_json


@contextmanager
def temp_test_output_file(prefix: str = 'kxicli-e2e-'):
    dir_name: str = str()
    inited: bool = False
    try:
        dir_name = mkdtemp(prefix=prefix)
        inited = True
        output_file_name = str(Path(dir_name).joinpath('output-values.yaml'))
        yield output_file_name
    finally:
        if inited:
            shutil.rmtree(dir_name)


@contextmanager
def temp_config_file(prefix: str = 'kxicli-config-', file_name='test-cli-config'):
    dir_name: str = str()
    inited: bool = False
    try:
        dir_name = mkdtemp(prefix=prefix)
        inited = True
        output_file_name = str(Path(dir_name).joinpath(file_name))
        shutil.copyfile(common.config.config_file, output_file_name)
        common.config.config_file = output_file_name
        yield output_file_name
    finally:
        if inited:
            shutil.rmtree(dir_name)
            common.config.config_file = test_cli_config_static
            common.config.load_config("default")


def compare_files(file1: str, file2: str):
    if os.name == 'nt':
        with temp_test_output_file() as temp_file1:
            with open(temp_file1, 'w', newline='\n') as tf, open(file1, 'r') as of:
                for line in of.readlines():
                    tf.write(line)
            return filecmp.cmp(temp_file1, file2, shallow=False)
    else:
        return filecmp.cmp(file1, file2, shallow=False)


def mocked_create_secret(namespace, name, secret_type, data=None, string_data=None):
    print(f'Secret {name} successfully created')

def mock_validate_secret(mocker):
    # Returns that the secret is valid and there are no missing keys
    mocker.patch('kxicli.commands.install.validate_secret', return_value=(True, []))

def mocked_patch_secret(namespace, name, secret_type, data=None, string_data=None):
    print(f'Secret {name} successfully updated')

def raise_not_found(**kwargs):
    """Helper function to test try/except blocks"""
    raise k8s.client.rest.ApiException(status=404)

def return_none(**kwargs):
    return None

def mock_read_create_patch_secret(mocker):
    # mock Kubernetes get API to raise a not found exception
    mock = mocker.patch('kubernetes.client.CoreV1Api')
    mock.return_value.read_namespaced_secret.side_effect = raise_not_found
    mocker.patch('kxicli.commands.install.create_secret', mocked_create_secret)
    mocker.patch('kxicli.commands.install.patch_secret', mocked_patch_secret)

def mocked_read_secret(namespace, name):
    install_secret = main.install.build_install_secret(test_vals)
    return main.install.get_secret_body(name, 'Opaque', data=install_secret)

def mock_read_secret(mocker):
    mocker.patch('kxicli.commands.install.read_secret', mocked_read_secret)

def mocked_helm_add_repo(repo, url, username, password):
    pass

def mocked_helm_list_returns_empty_json(base_command):
    return '[]'

def mock_delete_crd(mocker):
    global delete_crd_params
    delete_crd_params = []
    global crd_exists_flag
    crd_exists_flag = True
    mocker.patch('kxicli.common.delete_crd', mocked_delete_crd)
    
def mocked_delete_crd(name):
    print(f'Deleting CRD {name}')
    global delete_crd_params
    delete_crd_params.append(name)
    global crd_exists_flag
    crd_exists_flag = False

def mocked_copy_secret(name, from_ns, to_ns):
    global copy_secret_params
    copy_secret_params.append((name, from_ns, to_ns))
    pass

def mock_copy_secret(mocker):
    global copy_secret_params
    copy_secret_params = []
    mocker.patch('kxicli.commands.install.copy_secret', mocked_copy_secret)

def mocked_return_true(name):
    return True

def mocked_return_false(name):
    return False

def mocked_k8s_list_empty_config():
    return ([], {'context':()})

def mocked_create_namespace(namespace):
    pass

def mock_create_namespace(mocker):
   mocker.patch('kxicli.commands.install.create_namespace', mocked_create_namespace)

def mocked_subprocess_run(base_command, check=True, input=None, text=None):
    global insights_installed_flag
    global operator_installed_flag
    global crd_exists_flag
    global subprocess_run_command
    global subprocess_run_args
    subprocess_run_command.append(base_command)
    subprocess_run_args = (check, input, text)
    if base_command == ['helm', 'uninstall', 'insights', '--namespace', test_namespace]:
        insights_installed_flag = False
    elif base_command == ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator']:
        operator_installed_flag = False
    elif [base_command[i] for i in [0,1,-2,-1]] == ['helm', 'install', '--namespace', 'kxi-operator']:
        operator_installed_flag = True
    elif [base_command[i] for i in [0,1,-2,-1]] == ['helm', 'install', '--namespace', test_namespace]:
        insights_installed_flag = True
        crd_exists_flag = True

def mock_subprocess_run(mocker):
    global subprocess_run_command
    subprocess_run_command = []
    mocker.patch('subprocess.run', mocked_subprocess_run)

def mock_set_insights_operator_and_crd_installed_state(mocker, insights_flag, operator_flag, crd_flag):
    global insights_installed_flag
    global operator_installed_flag
    global crd_exists_flag
    insights_installed_flag = insights_flag
    operator_installed_flag = operator_flag
    crd_exists_flag = crd_flag
    mocker.patch('kxicli.commands.install.insights_installed', mocked_insights_installed)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_operator_installed)
    mocker.patch('kxicli.common.crd_exists', mocked_crd_exists)

def mocked_insights_installed(release, namespace):
    return insights_installed_flag

def mocked_operator_installed(release):
    return operator_installed_flag

def mocked_crd_exists(name):
    return crd_exists_flag

def mock_secret_helm_add(mocker):
    mock_read_create_patch_secret(mocker)
    mocker.patch('kxicli.commands.install.helm_add_repo', mocked_helm_add_repo)

def mock_list_assembly(namespace):
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)
    return {'items': [test_asm]}

def mock_list_assembly_multiple(namespace):
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)
    test_asm_2 = copy.deepcopy(test_asm)
    test_asm_2['metadata']['name'] = test_asm_name + '_2'
    return {'items': [test_asm,test_asm_2]}

def mock_delete_assembly(mocker):
    CUSTOM_OBJECT_API = 'kubernetes.client.CustomObjectsApi'
    PREFERRED_VERSION_FUNC = 'kxicli.commands.assembly.get_preferred_api_version'
    PREFERRED_VERSION = 'v1'
    mock_instance = mocker.patch(CUSTOM_OBJECT_API).return_value
    mocker.patch(PREFERRED_VERSION_FUNC, return_value=PREFERRED_VERSION)
    mock_instance.return_value.delete_namespaced_custom_object.return_value = return_none
    mock_instance.get_namespaced_custom_object.side_effect = raise_not_found

def mock_create_assembly(namespace, body, wait=None):
    asm_name = body['metadata']['name']
    print(f'Custom assembly resource {asm_name} created!')
    running_assembly[asm_name] = True

def upgrades_mocks(mocker):
    mock_subprocess_run(mocker)
    mock_create_namespace(mocker)
    mock_read_secret(mocker)
    mock_copy_secret(mocker)
    mock_delete_crd(mocker)
    mock_delete_assembly(mocker)
    mocker.patch('kxicli.commands.assembly._get_assemblies_list', mock_list_assembly)
    mocker.patch('kxicli.commands.assembly._create_assembly', mock_create_assembly)

def test_install_setup_when_creating_secrets(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:

        runner = CliRunner()
        with runner.isolated_filesystem():
            # these are responses to the various prompts
            user_input = f"""{test_host}
{test_chart_repo_name}
{test_chart_repo_url}
{test_user}
{test_pass}
n
{test_lic_file}
{test_image_repo}
n
n
{test_user}
{test_pass}
n
n
{test_pass}
{test_pass}
n
{test_pass}
{test_pass}
n
n
n
"""
            result = runner.invoke(main.cli, ['install', 'setup', '--output-file', test_output_file], input=user_input)

            # Transcript here is not intended because multi line strings are
            # interpreted directly including indentation
            expected_output = f"""KX Insights Install Setup

Running in namespace {test_namespace} on the cluster {test_cluster}

Please enter the hostname for the installation: {test_host}

Chart details
Please enter a name for the chart repository to set locally [{common.get_default_val('chart.repo.name')}]: {test_chart_repo_name}
Please enter the chart repository URL to pull charts from [{common.get_default_val('chart.repo.url')}]: {test_chart_repo_url}
Please enter the username for the chart repository: {test_user}
Please enter the password for the chart repository (input hidden): 

License details
Do you have an existing license secret [y/N]: n
Please enter the path to your kdb license: {test_lic_file}
Secret kxi-license successfully created

Image repository
Please enter the image repository to pull images from [registry.dl.kx.com]: {test_image_repo}
Do you have an existing image pull secret for {test_image_repo} [y/N]: n
Credentials {test_user}@{test_image_repo} exist in {test_docker_config_json}, do you want to use these [y/N]: n
Please enter the username for {test_image_repo}: {test_user}
Please enter the password for {test_user} (input hidden): 
Secret kxi-nexus-pull-secret successfully created

Client certificate issuer
Do you have an existing client certificate issuer [y/N]: n
Secret kxi-certificate successfully created

Keycloak
Do you have an existing keycloak secret [y/N]: n
Please enter the Keycloak Admin password (input hidden): 
Please enter the Keycloak WildFly Management password (input hidden): 
Secret kxi-keycloak successfully created
Do you have an existing keycloak postgresql secret [y/N]: n
Please enter the Postgresql postgres password (input hidden): 
Please enter the Postgresql user password (input hidden): 
Secret kxi-postgresql successfully created
Do you want to set a secret for the gui service account explicitly [y/N]: n
Randomly generating client secret for gui and setting in values file, record this value for reuse during upgrade
Persisting option guiClientSecret to file {test_cli_config}
Do you want to set a secret for the operator service account explicitly [y/N]: n
Randomly generating client secret for operator and setting in values file, record this value for reuse during upgrade
Persisting option operatorClientSecret to file {test_cli_config}

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""

        assert result.exit_code == 0
        assert result.output == expected_output

def test_install_setup_when_providing_secrets(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    mock_validate_secret(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:

        runner = CliRunner()
        with runner.isolated_filesystem():
            # these are responses to the various prompts
            user_input = f"""{test_host}
{test_chart_repo_name}
{test_chart_repo_url}
{test_user}
{test_pass}
y
{common.get_default_val('license.secret')}
{test_image_repo}
y
{common.get_default_val('image.pullSecret')}
y
{common.get_default_val('client.cert.secret')}
y
{common.get_default_val('keycloak.secret')}
y
{common.get_default_val('keycloak.postgresqlSecret')}
y
gui-secret
y
operator-secret
n
"""
            result = runner.invoke(main.cli, ['install', 'setup', '--output-file', test_output_file], input=user_input)

            # Transcript here is not intended because multi line strings are
            # interpreted directly including indentation
            expected_output = f"""KX Insights Install Setup

Running in namespace {test_namespace} on the cluster {test_cluster}

Please enter the hostname for the installation: {test_host}

Chart details
Please enter a name for the chart repository to set locally [{common.get_default_val('chart.repo.name')}]: {test_chart_repo_name}
Please enter the chart repository URL to pull charts from [{common.get_default_val('chart.repo.url')}]: {test_chart_repo_url}
Please enter the username for the chart repository: {test_user}
Please enter the password for the chart repository (input hidden): 

License details
Do you have an existing license secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('license.secret')}

Image repository
Please enter the image repository to pull images from [registry.dl.kx.com]: {test_image_repo}
Do you have an existing image pull secret for {test_image_repo} [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('image.pullSecret')}

Client certificate issuer
Do you have an existing client certificate issuer [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('client.cert.secret')}

Keycloak
Do you have an existing keycloak secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('keycloak.secret')}
Do you have an existing keycloak postgresql secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('keycloak.postgresqlSecret')}
Do you want to set a secret for the gui service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option guiClientSecret to file {test_cli_config}
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option operatorClientSecret to file {test_cli_config}

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""
        assert result.exit_code == 0
        assert result.output == expected_output
        assert compare_files(test_output_file, test_val_file)
        with open(test_cli_config, "r") as f:
            assert f.read() == """[default]
hostname = https://test.kx.com
namespace = test
client.id = client
client.secret = secret
guiClientSecret = gui-secret
operatorClientSecret = operator-secret

"""

def test_install_setup_when_passed_license_env_var_in_command_line(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    mock_validate_secret(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:

        runner = CliRunner()
        with runner.isolated_filesystem():
            # these are responses to the various prompts
            user_input = f"""{test_host}
{test_chart_repo_name}
{test_chart_repo_url}
{test_user}
{test_pass}
y
{common.get_default_val('license.secret')}
{test_image_repo}
y
{common.get_default_val('image.pullSecret')}
y
{common.get_default_val('client.cert.secret')}
y
{common.get_default_val('keycloak.secret')}
y
{common.get_default_val('keycloak.postgresqlSecret')}
y
gui-secret
y
operator-secret
n
"""
            result = runner.invoke(main.cli, ['install', 'setup', '--output-file', test_output_file, '--license-as-env-var', 'True'], input=user_input)

            # Transcript here is not intended because multi line strings are
            # interpreted directly including indentation
            expected_output = f"""KX Insights Install Setup

Running in namespace {test_namespace} on the cluster {test_cluster}

Please enter the hostname for the installation: {test_host}

Chart details
Please enter a name for the chart repository to set locally [{common.get_default_val('chart.repo.name')}]: {test_chart_repo_name}
Please enter the chart repository URL to pull charts from [{common.get_default_val('chart.repo.url')}]: {test_chart_repo_url}
Please enter the username for the chart repository: {test_user}
Please enter the password for the chart repository (input hidden): 

License details
Do you have an existing license secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('license.secret')}

Image repository
Please enter the image repository to pull images from [registry.dl.kx.com]: {test_image_repo}
Do you have an existing image pull secret for {test_image_repo} [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('image.pullSecret')}

Client certificate issuer
Do you have an existing client certificate issuer [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('client.cert.secret')}

Keycloak
Do you have an existing keycloak secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('keycloak.secret')}
Do you have an existing keycloak postgresql secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('keycloak.postgresqlSecret')}
Do you want to set a secret for the gui service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option guiClientSecret to file {test_cli_config}
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option operatorClientSecret to file {test_cli_config}

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""

        assert result.exit_code == 0
        assert result.output == expected_output
        assert compare_files(test_output_file, test_output_file_lic_env_var)


def test_install_setup_overwrites_when_values_file_exists(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    mock_validate_secret(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        f = open(test_output_file, 'w')
        f.write('a test values file')
        f.close()

        runner = CliRunner()
        with runner.isolated_filesystem():
            # these are responses to the various prompts
            user_input = f"""{test_host}
{test_chart_repo_name}
{test_chart_repo_url}
{test_user}
{test_pass}
y
{common.get_default_val('license.secret')}
{test_image_repo}
y
{common.get_default_val('image.pullSecret')}
y
{common.get_default_val('client.cert.secret')}
y
{common.get_default_val('keycloak.secret')}
y
{common.get_default_val('keycloak.postgresqlSecret')}
y
gui-secret
y
operator-secret
n
y
"""
            result = runner.invoke(main.cli, ['install', 'setup', '--output-file', test_output_file], input=user_input)

            # Transcript here is not intended because multi line strings are
            # interpreted directly including indentation
            expected_output = f"""KX Insights Install Setup

Running in namespace {test_namespace} on the cluster {test_cluster}

Please enter the hostname for the installation: {test_host}

Chart details
Please enter a name for the chart repository to set locally [{common.get_default_val('chart.repo.name')}]: {test_chart_repo_name}
Please enter the chart repository URL to pull charts from [{common.get_default_val('chart.repo.url')}]: {test_chart_repo_url}
Please enter the username for the chart repository: {test_user}
Please enter the password for the chart repository (input hidden): 

License details
Do you have an existing license secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('license.secret')}

Image repository
Please enter the image repository to pull images from [registry.dl.kx.com]: {test_image_repo}
Do you have an existing image pull secret for {test_image_repo} [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('image.pullSecret')}

Client certificate issuer
Do you have an existing client certificate issuer [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('client.cert.secret')}

Keycloak
Do you have an existing keycloak secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('keycloak.secret')}
Do you have an existing keycloak postgresql secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('keycloak.postgresqlSecret')}
Do you want to set a secret for the gui service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option guiClientSecret to file {test_cli_config}
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option operatorClientSecret to file {test_cli_config}

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n

{test_output_file} file exists. Do you want to overwrite it with a new values file? [y/N]: y
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""
        assert result.exit_code == 0
        assert result.output == expected_output
        assert compare_files(test_output_file, test_val_file)

def test_install_setup_creates_new_when_values_file_exists(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    mock_validate_secret(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        f = open(test_output_file, 'w')
        f.write("a test values file")
        f.close()

        runner = CliRunner()
        with runner.isolated_filesystem():
            # these are responses to the various prompts
            user_input = f"""{test_host}
{test_chart_repo_name}
{test_chart_repo_url}
{test_user}
{test_pass}
y
{common.get_default_val('license.secret')}
{test_image_repo}
y
{common.get_default_val('image.pullSecret')}
y
{common.get_default_val('client.cert.secret')}
y
{common.get_default_val('keycloak.secret')}
y
{common.get_default_val('keycloak.postgresqlSecret')}
y
gui-secret
y
operator-secret
n
n
{test_output_file}_new
"""
            result = runner.invoke(main.cli, ['install', 'setup', '--output-file', test_output_file], input=user_input)

            # Transcript here is not intended because multi line strings are
            # interpreted directly including indentation
            expected_output = f"""KX Insights Install Setup

Running in namespace {test_namespace} on the cluster {test_cluster}

Please enter the hostname for the installation: {test_host}

Chart details
Please enter a name for the chart repository to set locally [{common.get_default_val('chart.repo.name')}]: {test_chart_repo_name}
Please enter the chart repository URL to pull charts from [{common.get_default_val('chart.repo.url')}]: {test_chart_repo_url}
Please enter the username for the chart repository: {test_user}
Please enter the password for the chart repository (input hidden): 

License details
Do you have an existing license secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('license.secret')}

Image repository
Please enter the image repository to pull images from [registry.dl.kx.com]: {test_image_repo}
Do you have an existing image pull secret for {test_image_repo} [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('image.pullSecret')}

Client certificate issuer
Do you have an existing client certificate issuer [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('client.cert.secret')}

Keycloak
Do you have an existing keycloak secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('keycloak.secret')}
Do you have an existing keycloak postgresql secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('keycloak.postgresqlSecret')}
Do you want to set a secret for the gui service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option guiClientSecret to file {test_cli_config}
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option operatorClientSecret to file {test_cli_config}

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n

{test_output_file} file exists. Do you want to overwrite it with a new values file? [y/N]: n
Please enter the path to write the values file for the install: {test_output_file}_new
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}_new

"""
        assert result.exit_code == 0
        assert result.output == expected_output
        assert compare_files(f'{test_output_file}_new', test_val_file)
        with open(test_output_file, "r") as f:
            assert f.read() == "a test values file"             # assert that the original file is unchanged

def test_install_run_when_provided_file(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, True, True)
    mock_create_namespace(mocker)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file])
        expected_output = f"""
kxi-operator already installed
Installing chart kx-insights/insights with values file from {test_val_file}
"""    
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm', 'install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]]

def test_install_run_when_no_file_provided(mocker):
    mock_read_create_patch_secret(mocker)
    mock_subprocess_run(mocker)
    mocker.patch('subprocess.check_output', mocked_helm_list_returns_empty_json)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    mock_create_namespace(mocker)
    mock_validate_secret(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        f = open(test_output_file, 'w')
        f.write("a test values file")
        f.close()

        runner = CliRunner()
        with runner.isolated_filesystem():
            # these are responses to the various prompts
                    # these are responses to the various prompts
            user_input = f"""{test_host}
{test_chart_repo_name}
{test_chart_repo_url}
{test_user}
{test_pass}
y
{common.get_default_val('license.secret')}
{test_image_repo}
y
{common.get_default_val('image.pullSecret')}
y
{common.get_default_val('client.cert.secret')}
y
{common.get_default_val('keycloak.secret')}
y
{common.get_default_val('keycloak.postgresqlSecret')}
y
gui-secret
y
operator-secret
n
n
"""
            result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3'], input=user_input)

            expected_output = f"""No values file provided, invoking "kxi install setup"

KX Insights Install Setup

Running in namespace {test_namespace} on the cluster {test_cluster}

Please enter the hostname for the installation: {test_host}

Chart details
Please enter a name for the chart repository to set locally [kx-insights]: {test_chart_repo_name}
Please enter the chart repository URL to pull charts from [https://nexus.dl.kx.com/repository/kx-insights-charts]: {test_chart_repo_url}
Please enter the username for the chart repository: {test_user}
Please enter the password for the chart repository (input hidden): 

License details
Do you have an existing license secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('license.secret')}

Image repository
Please enter the image repository to pull images from [registry.dl.kx.com]: {test_image_repo}
Do you have an existing image pull secret for {test_image_repo} [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('image.pullSecret')}

Client certificate issuer
Do you have an existing client certificate issuer [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('client.cert.secret')}

Keycloak
Do you have an existing keycloak secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('keycloak.secret')}
Do you have an existing keycloak postgresql secret [y/N]: y
Please enter the name of the existing secret: {common.get_default_val('keycloak.postgresqlSecret')}
Do you want to set a secret for the gui service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option guiClientSecret to file {test_cli_config}
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option operatorClientSecret to file {test_cli_config}

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in values.yaml


kxi-operator not found. Do you want to install it? [Y/n]: n
Installing chart internal-nexus-dev/insights with values file from values.yaml
"""    
        assert result.exit_code == 0
        assert result.output == expected_output
        assert subprocess_run_command == [
            ['helm', 'repo', 'add', '--username', test_user, '--password', test_pass, test_chart_repo_name, test_chart_repo_url],
            ['helm', 'install', '-f', 'values.yaml', 'insights', test_chart_repo_name+'/insights', '--version', '1.2.3', '--namespace', test_namespace]
        ]

def test_install_run_when_provided_secret(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, True, True)
    mock_create_namespace(mocker)
    mock_read_secret(mocker)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--install-config-secret', test_install_secret])
        expected_output = f"""
kxi-operator already installed
Installing chart kx-insights/insights with values from secret
"""
    with open(test_val_file, 'r') as values_file:
        values = str(values_file.read())
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm', 'install', '-f', '-', 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]]
    assert subprocess_run_args == (True, values, True)

def test_install_run_when_provided_file_and_secret(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, True, True)
    mock_create_namespace(mocker)
    mock_read_secret(mocker)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file, '--install-config-secret', test_install_secret])
        expected_output = f"""
kxi-operator already installed
Installing chart kx-insights/insights with values from secret and values file from {test_val_file}
"""
    with open(test_val_file, 'r') as values_file:
        values = str(values_file.read())
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm', 'install', '-f', '-', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]]
    assert subprocess_run_args == (True, values, True)

def test_install_run_installs_operator(mocker):
    mock_subprocess_run(mocker)
    mock_create_namespace(mocker)
    mock_copy_secret(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    global copy_secret_params
    copy_secret_params = []

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file], input=user_input)
        expected_output = f"""
kxi-operator not found. Do you want to install it? [Y/n]: y
Installing chart kx-insights/kxi-operator with values file from {test_val_file}
Installing chart kx-insights/insights with values file from {test_val_file}
"""    
    assert result.exit_code == 0
    assert result.output == expected_output
    assert copy_secret_params == [('kxi-nexus-pull-secret',test_namespace,'kxi-operator'),('kxi-license',test_namespace,'kxi-operator')]
    assert subprocess_run_command == [
        ['helm', 'install', '-f', test_val_file, 'insights', test_operator_chart, '--version', '1.2.3', '--namespace', 'kxi-operator'],
        ['helm', 'install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
        ]


def test_install_run_force_installs_operator(mocker):
    mock_subprocess_run(mocker)
    mock_create_namespace(mocker)
    mock_copy_secret(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    global copy_secret_params
    copy_secret_params = []

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file, '--force'])
        expected_output = f"""Installing chart kx-insights/kxi-operator with values file from {test_val_file}
Installing chart kx-insights/insights with values file from {test_val_file}
"""    
    assert result.exit_code == 0
    assert result.output == expected_output
    assert copy_secret_params == [('kxi-nexus-pull-secret',test_namespace,'kxi-operator'),('kxi-license',test_namespace,'kxi-operator')]
    assert subprocess_run_command == [
        ['helm', 'install', '-f', test_val_file, 'insights', test_operator_chart, '--version', '1.2.3', '--namespace', 'kxi-operator'],
        ['helm', 'install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
        ]


def test_install_run_installs_operator_with_modified_secrets(mocker):
    mock_subprocess_run(mocker)
    mock_create_namespace(mocker)
    mock_read_secret(mocker)
    mock_copy_secret(mocker)    
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    global test_vals
    global copy_secret_params
    copy_secret_params = []
    test_vals_backup = copy.deepcopy(test_vals)
    test_vals['global']['imagePullSecrets'][0]['name'] = 'new-image-pull-secret'
    test_vals['global']['license']['secretName'] = 'new-license-secret'

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--install-config-secret', test_install_secret], input=user_input)
        expected_output = f"""
kxi-operator not found. Do you want to install it? [Y/n]: y
Installing chart kx-insights/kxi-operator with values from secret
Installing chart kx-insights/insights with values from secret
"""    
    assert result.exit_code == 0
    assert result.output == expected_output
    assert copy_secret_params == [('new-image-pull-secret',test_namespace,'kxi-operator'),('new-license-secret',test_namespace,'kxi-operator')]
    assert subprocess_run_command == [
        ['helm', 'install', '-f', '-', 'insights', test_operator_chart, '--version', '1.2.3', '--namespace', 'kxi-operator'],
        ['helm', 'install', '-f', '-', 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
        ]
    assert subprocess_run_args == (True, yaml.dump(test_vals), True)
    test_vals = test_vals_backup

def test_install_run_when_no_context_set(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, True, True)
    mock_create_namespace(mocker)
    mocker.patch('kubernetes.config.list_kube_config_contexts', mocked_k8s_list_empty_config)
    
    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file])
        expected_output = f"""
Please enter a namespace to run in [test]: 

kxi-operator already installed
Installing chart kx-insights/insights with values file from {test_val_file}
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm', 'install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace', 'test']]

def test_delete(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, False, False)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'delete'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace {test_namespace}
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm','uninstall','insights','--namespace',test_namespace]]
    assert delete_crd_params == []


def test_list_versions_default_repo(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, False, False)
    
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'list-versions'])
        expected_output = f"""Listing available KX Insights versions in repo kx-insights
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm', 'search', 'repo', test_chart]]

def test_list_versions_custom_repo(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, False, False)

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'list-versions', '--chart-repo-name', test_chart_repo_name])
        expected_output = f"""Listing available KX Insights versions in repo {test_chart_repo_name}
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm', 'search', 'repo', test_chart_repo_name+'/insights']]
    
def test_delete_specify_release(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, False, False)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'delete', '--release','atestrelease'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release atestrelease in namespace {test_namespace}
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm','uninstall','atestrelease','--namespace', test_namespace]]
    assert delete_crd_params == []


def test_delete_does_not_prompt_to_remove_operator_and_crd_when_insights_exists(mocker):
    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""n
"""
        result = runner.invoke(main.cli, ['install', 'delete'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: n
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == []
    assert delete_crd_params == []

def test_delete_removes_insights_and_operator(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
y
n
"""
        result = runner.invoke(main.cli, ['install', 'delete'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace {test_namespace}

The kxi-operator is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace kxi-operator

The assemblies CRDs ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com'] exist. Do you want to delete them? [y/N]: n
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'uninstall', 'insights','--namespace', test_namespace],
        ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator']
        ]
    assert delete_crd_params == []


def test_delete_removes_insights_and_crd(mocker):
    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
n
y
"""
        result = runner.invoke(main.cli, ['install', 'delete'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace {test_namespace}

The kxi-operator is deployed. Do you want to uninstall? [y/N]: n

The assemblies CRDs ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com'] exist. Do you want to delete them? [y/N]: y
Deleting CRD assemblies.insights.kx.com
Deleting CRD assemblyresources.insights.kx.com
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm', 'uninstall', 'insights','--namespace', test_namespace]]
    assert delete_crd_params == test_crds

def test_delete_removes_insights_operator_and_crd(mocker):
    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
y
y
"""
        result = runner.invoke(main.cli, ['install', 'delete'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace {test_namespace}

The kxi-operator is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace kxi-operator

The assemblies CRDs ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com'] exist. Do you want to delete them? [y/N]: y
Deleting CRD assemblies.insights.kx.com
Deleting CRD assemblyresources.insights.kx.com
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'uninstall', 'insights','--namespace', test_namespace],
        ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator']
    ]
    assert delete_crd_params == test_crds

def test_delete_force_removes_insights_operator_and_crd(mocker):
    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'delete', '--force'])
        expected_output = f"""Uninstalling release insights in namespace {test_namespace}
Uninstalling release insights in namespace kxi-operator
Deleting CRD assemblies.insights.kx.com
Deleting CRD assemblyresources.insights.kx.com
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'uninstall', 'insights','--namespace', test_namespace],
        ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator']
    ]
    assert delete_crd_params == test_crds

def test_delete_from_given_namespace(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, False, False)
    global delete_crd_params
    delete_crd_params = []

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'delete','--namespace','a_test_namespace'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace a_test_namespace
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm','uninstall','insights','--namespace','a_test_namespace']]
    assert delete_crd_params == []


def test_delete_when_insights_not_installed(mocker):
    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, True, True)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""n
n
"""
        result = runner.invoke(main.cli, ['install', 'delete'], input=user_input)
        expected_output = f"""
KX Insights installation not found

The kxi-operator is deployed. Do you want to uninstall? [y/N]: n

The assemblies CRDs ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com'] exist. Do you want to delete them? [y/N]: n
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == []
    assert delete_crd_params == []

def test_install_when_not_deploying_keycloak(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        shutil.copyfile(expected_test_output_file, test_output_file)
        # Ideally would patch sys.argv with args but can't find a way to get this to stick
        #   'mocker.patch('sys.argv', args)'
        # doesn't seem to be persist into the runner.invoke
        args = ['install', 'setup', '--keycloak-auth-url', test_auth_url, '--output-file', test_output_file]
        mocker.patch('kxicli.commands.install.deploy_keycloak', lambda:False)

        runner = CliRunner()
        with runner.isolated_filesystem():
            # these are responses to the various prompts
            user_input = f"""{test_host}
{test_chart_repo_name}
{test_chart_repo_url}
{test_user}
{test_pass}
n
{test_lic_file}
{test_image_repo}
n
n
{test_user}
{test_pass}
n
y
gui-secret
y
operator-secret
n
y
"""
            result = runner.invoke(main.cli, args, input=user_input)

            # Transcript here is not intended because multi line strings are
            # interpreted directly including indentation
            expected_output = f"""KX Insights Install Setup

Running in namespace {test_namespace} on the cluster {test_cluster}

Please enter the hostname for the installation: {test_host}

Chart details
Please enter a name for the chart repository to set locally [{common.get_default_val('chart.repo.name')}]: {test_chart_repo_name}
Please enter the chart repository URL to pull charts from [{common.get_default_val('chart.repo.url')}]: {test_chart_repo_url}
Please enter the username for the chart repository: {test_user}
Please enter the password for the chart repository (input hidden): 

License details
Do you have an existing license secret [y/N]: n
Please enter the path to your kdb license: {test_lic_file}
Secret kxi-license successfully created

Image repository
Please enter the image repository to pull images from [registry.dl.kx.com]: {test_image_repo}
Do you have an existing image pull secret for {test_image_repo} [y/N]: n
Credentials {test_user}@{test_image_repo} exist in {test_docker_config_json}, do you want to use these [y/N]: n
Please enter the username for {test_image_repo}: {test_user}
Please enter the password for {test_user} (input hidden): 
Secret kxi-nexus-pull-secret successfully created

Client certificate issuer
Do you have an existing client certificate issuer [y/N]: n
Secret kxi-certificate successfully created

Keycloak
Do you want to set a secret for the gui service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option guiClientSecret to file {test_cli_config}
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 
Persisting option operatorClientSecret to file {test_cli_config}

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n

{test_output_file} file exists. Do you want to overwrite it with a new values file? [y/N]: y
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""

        assert result.exit_code == 0
        assert result.output == expected_output
        assert compare_files(test_output_file, test_val_file_shared_keycloak)

def test_get_values_returns_error_when_does_not_exist(mocker):
    mocker.patch('kxicli.commands.install.read_secret', return_none)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'get-values'])

    assert result.exit_code == 0
    assert result.output == f"""error=Cannot find values secret {common.get_default_val('install.configSecret')}\n\n"""

def test_get_values_returns_decoded_secret(mocker):
    mock_read_secret(mocker)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'get-values'])

    assert result.exit_code == 0
    with open(test_val_file, 'r') as f:
        assert result.output == f.read() + '\n'

def test_upgrade(mocker):
    upgrades_mocks(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    if os.path.exists(test_asm_backup):
        os.remove(test_asm_backup)
    with open(test_asm_file) as f:
        test_asm_file_contents = yaml.safe_load(f)
    with open(test_val_file, 'r') as values_file:
        values = str(values_file.read())
    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
y
y
y
y
"""
        result = runner.invoke(main.cli, ['install', 'upgrade', '--version', '1.2.3', '--install-config-secret', test_install_secret, '--assembly-backup-filepath', test_asm_backup], input=user_input)
        expected_output = f"""Upgrading KX Insights

Backing up assemblies
Persisted assembly definitions for ['{test_asm_name}'] to {test_asm_backup}

Tearing down assemblies
Assembly data will be persisted and state will be recovered post-upgrade
Tearing down assembly {test_asm_name}
Are you sure you want to teardown {test_asm_name} [y/N]: y
Waiting for assembly to be torn down

Uninstalling insights and operator

KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace {test_namespace}

The kxi-operator is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace kxi-operator

The assemblies CRDs ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com'] exist. Do you want to delete them? [y/N]: y
Deleting CRD assemblies.insights.kx.com
Deleting CRD assemblyresources.insights.kx.com

Reinstalling insights and operator

kxi-operator not found. Do you want to install it? [Y/n]: y
Installing chart kx-insights/kxi-operator with values from secret
Installing chart kx-insights/insights with values from secret

Reapplying assemblies
Submitting assembly from {test_asm_backup}
Submitting assembly {test_asm_name}
Custom assembly resource {test_asm_name} created!

Upgrade to version 1.2.3 complete
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    with open(test_asm_backup) as f:
        assert yaml.safe_load(f) == {'items': [test_asm_file_contents]}
    assert subprocess_run_command == [
        ['helm', 'uninstall', 'insights','--namespace', test_namespace],
        ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator'],
        ['helm', 'install', '-f', '-', 'insights', test_operator_chart, '--version', '1.2.3', '--namespace', 'kxi-operator'],
        ['helm', 'install', '-f', '-', 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
    ]
    assert subprocess_run_args == (True, values, True)
    assert delete_crd_params == test_crds
    assert insights_installed_flag == True
    assert operator_installed_flag ==True
    assert crd_exists_flag == True
    assert running_assembly[test_asm_name] == True
    os.remove(test_asm_backup)

def test_upgrade_skips_to_install_when_not_running(mocker):
    upgrades_mocks(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    runner = CliRunner()
    user_input = f"""y
"""
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'upgrade', '--version', '1.2.3', '--install-config-secret', test_install_secret], input=user_input)
    expected_output = f"""Upgrading KX Insights
KX Insights is not deployed. Skipping to install

kxi-operator not found. Do you want to install it? [Y/n]: y
Installing chart kx-insights/kxi-operator with values from secret
Installing chart kx-insights/insights with values from secret

Upgrade to version 1.2.3 complete
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'install', '-f', '-', 'insights', test_operator_chart, '--version', '1.2.3', '--namespace', 'kxi-operator'],
        ['helm', 'install', '-f', '-', 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
    ]

def test_upgrade_when_user_declines_to_uninstall_insights(mocker):
    upgrades_mocks(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    if os.path.exists(test_asm_backup):
        os.remove(test_asm_backup)
    with open(test_asm_file) as f:
        test_asm_file_contents = yaml.safe_load(f)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'upgrade', '--version', '1.2.3', '--install-config-secret', test_install_secret, '--assembly-backup-filepath', test_asm_backup], input='y\nn\n')
    expected_output = f"""Upgrading KX Insights

Backing up assemblies
Persisted assembly definitions for ['{test_asm_name}'] to {test_asm_backup}

Tearing down assemblies
Assembly data will be persisted and state will be recovered post-upgrade
Tearing down assembly {test_asm_name}
Are you sure you want to teardown {test_asm_name} [y/N]: y
Waiting for assembly to be torn down

Uninstalling insights and operator

KX Insights is deployed. Do you want to uninstall? [y/N]: n

Reinstalling insights and operator

kxi-operator already installed

KX Insights already installed

Reapplying assemblies
Submitting assembly from {test_asm_backup}
Submitting assembly {test_asm_name}
Custom assembly resource {test_asm_name} created!
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    with open(test_asm_backup) as f:
        assert yaml.safe_load(f) == {'items': [test_asm_file_contents]}
    assert subprocess_run_command == []
    assert delete_crd_params == []
    assert insights_installed_flag == True
    assert operator_installed_flag ==True
    assert crd_exists_flag == True
    assert running_assembly[test_asm_name] == True
    os.remove(test_asm_backup)        


def test_upgrade_when_user_declines_to_teardown_assembly(mocker):
    upgrades_mocks(mocker)
    mocker.patch('kxicli.commands.assembly._get_assemblies_list', mock_list_assembly_multiple)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    if os.path.exists(test_asm_backup):
        os.remove(test_asm_backup)
    with open(test_asm_file) as f:
        test_asm_file_contents = yaml.safe_load(f)
    test_asm_file_contents_2 = copy.deepcopy(test_asm_file_contents)
    test_asm_file_contents_2['metadata']['name'] = test_asm_name + '_2'
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'upgrade', '--version', '1.2.3', '--filepath', test_val_file, '--assembly-backup-filepath', test_asm_backup], input='y\nn\n')
    expected_output = f"""Upgrading KX Insights

Backing up assemblies
Persisted assembly definitions for ['{test_asm_name}', '{test_asm_name+'_2'}'] to {test_asm_backup}

Tearing down assemblies
Assembly data will be persisted and state will be recovered post-upgrade
Tearing down assembly {test_asm_name}
Are you sure you want to teardown {test_asm_name} [y/N]: y
Waiting for assembly to be torn down
Tearing down assembly {test_asm_name+'_2'}
Are you sure you want to teardown {test_asm_name+'_2'} [y/N]: n
Not tearing down assembly {test_asm_name+'_2'}

Reapplying assemblies
Submitting assembly from {test_asm_backup}
Submitting assembly {test_asm_name}
Custom assembly resource {test_asm_name} created!
Submitting assembly {test_asm_name+'_2'}
Custom assembly resource {test_asm_name+'_2'} created!
"""
    assert result.exit_code == 0
    with open(test_asm_backup) as f:
        assert yaml.safe_load(f) == { 'items': 
            [
                test_asm_file_contents,
                test_asm_file_contents_2
            ]
        }
    assert subprocess_run_command == []
    assert delete_crd_params == []
    assert insights_installed_flag == True
    assert operator_installed_flag ==True
    assert crd_exists_flag == True
    assert running_assembly[test_asm_name] == True
    assert running_assembly[test_asm_name+'_2'] == True
    assert result.output == expected_output
    os.remove(test_asm_backup)
