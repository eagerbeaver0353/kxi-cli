"""This end 2 end test validates the inputs and outputs of the install command directly"""
import os
import base64
import yaml
import kubernetes as k8s
import filecmp
from click.testing import CliRunner
from kxicli import main
from kxicli import common
from kxicli.commands import assembly

common.config.load_config("default")

test_host = 'test.internal-insights.kx.com'
test_chart_repo_name = 'internal-nexus-dev'
test_chart_repo_url = 'https://nexus.internal-insights.kx.com/repository/kx-helm-charts-dev'
test_image_repo = 'test-repo.internal-insights.kx.com'
test_user = 'user'
test_pass = 'password'
test_auth_url = 'http://keycloak.keycloak.svc.cluster.local/auth/'
test_chart = 'kx-insights/insights'

test_val_file = os.path.dirname(__file__) + '/files/test-values.yaml'
test_val_file_shared_keycloak = os.path.dirname(__file__) + '/files/test-values-shared-keycloak.yaml'
test_k8s_config = os.path.dirname(__file__) + '/files/test-kube-config'
test_lic_file = os.path.dirname(__file__) + '/files/test-license'
test_output_file = os.path.dirname(__file__) + '/files/output-values.yaml'
test_output_file_lic_env_var = os.path.dirname(__file__) + '/files/output-values-license-as-env-var.yaml'
test_docker_config_json = os.path.dirname(__file__) + '/files/test-docker-config-json'
test_asm_file = os.path.dirname(__file__) + '/files/assembly-v1.yaml'
test_asm_name = 'basic-assembly' #As per contents of test_asm_file

_, active_context = k8s.config.list_kube_config_contexts()
test_namespace = active_context['context']['namespace']
test_cluster = active_context['context']['cluster']

delete_crd_params = []
insights_installed_flag = True
operator_installed_flag = True
crd_exists_flag = True
running_assembly = {}

# override where the command looks for the docker config json
# by default this is $HOME/.docker/config.json
main.install.docker_config_file_path = test_docker_config_json

def mocked_create_secret(namespace, name, secret_type, data=None, string_data=None):
    print(f'Secret {name} successfully created')

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

def mock_read_secret(namespace, name):
    with open(test_val_file, 'rb') as values_file:
        data = yaml.full_load(values_file)
    install_secret = main.install.build_install_secret(data)

    return main.install.get_secret_body(name, 'Opaque', data=install_secret)

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
    pass

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
    if base_command == ['helm', 'uninstall', 'insights']:
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

def mock_insights_operator_and_crd_installed(mocker):
    global insights_installed_flag
    global operator_installed_flag
    global crd_exists_flag
    insights_installed_flag = True
    operator_installed_flag = True
    crd_exists_flag = True
    mocker.patch('kxicli.commands.install.insights_installed', mocked_insights_installed)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_operator_installed)
    mocker.patch('kxicli.common.crd_exists', mocked_crd_exists)

def mocked_insights_installed(name):
    return insights_installed_flag

def mocked_operator_installed(name):
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

def mock_delete_assembly(namespace, name, wait, force):
    print(f'Deleting assembly {name}')
    print(f'Are you sure you want to delete {name} [y/N]: y')
    running_assembly[name] = False

def mock_create_assembly(namespace, body, wait=None):
    asm_name = body['metadata']['name']
    print(f'Custom assembly resource {asm_name} created!')
    running_assembly[asm_name] = True

def test_install_setup_when_creating_secrets(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    os.remove(test_output_file)

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
Do you want to set a secret for the operator service account explicitly [y/N]: n
Randomly generating client secret for operator and setting in values file, record this value for reuse during upgrade

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
    os.remove(test_output_file)

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
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert filecmp.cmp(test_output_file, test_val_file)

def test_install_setup_when_passed_license_env_var_in_command_line(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    os.rename(test_output_file, f'{test_output_file}_bk')

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
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert filecmp.cmp(test_output_file, test_output_file_lic_env_var)
    os.rename(f'{test_output_file}_bk', test_output_file)

def test_install_setup_overwrites_when_values_file_exists(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    f = open(test_output_file, 'w')
    f.write('a test values file')

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
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n

{test_output_file} file exists. Do you want to overwrite it with a new values file? [y/N]: y
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert filecmp.cmp(test_output_file, test_val_file)

def test_install_setup_creates_new_when_values_file_exists(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
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
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 

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
    assert filecmp.cmp(f'{test_output_file}_new', test_val_file)
    f = open(test_output_file, "r")
    assert f.read() == "a test values file"             # assert that the original file is unchanged
    os.rename(f'{test_output_file}_new', test_output_file)

def test_install_run_when_provided_file(mocker):
    mock_subprocess_run(mocker)
    mock_insights_operator_and_crd_installed(mocker)
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
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mock_create_namespace(mocker)
    
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
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 

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
    mock_insights_operator_and_crd_installed(mocker)
    mock_create_namespace(mocker)
    mocker.patch('kxicli.commands.install.read_secret', mock_read_secret)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--install-config-secret', 'kxi-install-secret'])
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
    mock_insights_operator_and_crd_installed(mocker)
    mock_create_namespace(mocker)
    mocker.patch('kxicli.commands.install.read_secret', mock_read_secret)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file, '--install-config-secret', 'kxi-install-secret'])
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
    mocker.patch('kxicli.commands.install.copy_secret', mocked_copy_secret)    
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_false)
    mocker.patch('kxicli.common.crd_exists', mocked_return_false)

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
    assert subprocess_run_command == [
        ['helm', 'install', '-f', test_val_file, 'insights', 'kx-insights/kxi-operator', '--version', '1.2.3', '--namespace', 'kxi-operator'],
        ['helm', 'install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
        ]

def test_install_run_when_no_context_set(mocker):
    mock_subprocess_run(mocker)
    mock_insights_operator_and_crd_installed(mocker)
    mock_create_namespace(mocker)
    mocker.patch('kubernetes.config.list_kube_config_contexts', mocked_k8s_list_empty_config)
    
    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file])
        expected_output = f"""
Please enter a namespace to install in [kxi]: 

kxi-operator already installed
Installing chart kx-insights/insights with values file from {test_val_file}
"""
    print(result)
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm', 'install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace', 'kxi']]

def test_delete(mocker):
    mock_subprocess_run(mocker)
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_false)
    mocker.patch('kxicli.common.crd_exists', mocked_return_false)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'delete'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm','uninstall','insights']]
    assert delete_crd_params == []


def test_list_versions_default_repo(mocker):
    mock_subprocess_run(mocker)
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_false)
    mocker.patch('kxicli.common.crd_exists', mocked_return_false)
    
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
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_false)
    mocker.patch('kxicli.common.crd_exists', mocked_return_false)
    
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'list-versions', '--repo', test_chart_repo_name])
        expected_output = f"""Listing available KX Insights versions in repo {test_chart_repo_name}
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm', 'search', 'repo', test_chart_repo_name+'/insights']]
    
def test_delete_specify_release(mocker):
    mock_subprocess_run(mocker)
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_false)
    mocker.patch('kxicli.common.crd_exists', mocked_return_false)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'delete', '--release','atestrelease'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release atestrelease
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm','uninstall','atestrelease']]
    assert delete_crd_params == []


def test_delete_prompts_to_remove_insights_operator_and_crd(mocker):
    mock_subprocess_run(mocker)
    mocker.patch('kxicli.common.delete_crd', mocked_delete_crd)
    mock_insights_operator_and_crd_installed(mocker)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""n
n
n
"""
        result = runner.invoke(main.cli, ['install', 'delete'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: n

The kxi-operator is deployed. Do you want to uninstall? [y/N]: n

The assemblies CRDs ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com'] exist. Do you want to delete them? [y/N]: n
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == []
    assert delete_crd_params == []

def test_delete_removes_insights_and_operator(mocker):
    mock_subprocess_run(mocker)
    mock_insights_operator_and_crd_installed(mocker)

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
Uninstalling release insights

The kxi-operator is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace kxi-operator

The assemblies CRDs ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com'] exist. Do you want to delete them? [y/N]: n
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'uninstall', 'insights'],
        ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator']
        ]
    assert delete_crd_params == []


def test_delete_removes_insights_and_crd(mocker):
    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_insights_operator_and_crd_installed(mocker)

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
Uninstalling release insights

The kxi-operator is deployed. Do you want to uninstall? [y/N]: n

The assemblies CRDs ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com'] exist. Do you want to delete them? [y/N]: y
Deleting CRD assemblies.insights.kx.com
Deleting CRD assemblyresources.insights.kx.com
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [['helm', 'uninstall', 'insights']]
    assert delete_crd_params == ['assemblies.insights.kx.com','assemblyresources.insights.kx.com']

def test_delete_removes_insights_operator_and_crd(mocker):
    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_insights_operator_and_crd_installed(mocker)

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
Uninstalling release insights

The kxi-operator is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace kxi-operator

The assemblies CRDs ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com'] exist. Do you want to delete them? [y/N]: y
Deleting CRD assemblies.insights.kx.com
Deleting CRD assemblyresources.insights.kx.com
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'uninstall', 'insights'],
        ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator']
    ]
    assert delete_crd_params == ['assemblies.insights.kx.com','assemblyresources.insights.kx.com']

def test_install_when_not_deploying_keycloak(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)

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
Do you want to set a secret for the operator service account explicitly [y/N]: y
Please enter the secret (input hidden): 

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n

{test_output_file} file exists. Do you want to overwrite it with a new values file? [y/N]: y
Secret {common.get_default_val('install.configSecret')} successfully created

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""

    assert result.exit_code == 0
    assert result.output == expected_output
    assert filecmp.cmp(test_output_file, test_val_file_shared_keycloak)

def test_get_values_returns_error_when_does_not_exist(mocker):
    mocker.patch('kxicli.commands.install.read_secret', return_none)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'get-values'])

    assert result.exit_code == 0
    assert result.output == f"""error=Cannot find values secret {common.get_default_val('install.configSecret')}\n\n"""

def test_get_values_returns_decoded_secret(mocker):
    mocker.patch('kxicli.commands.install.read_secret', mock_read_secret)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'get-values'])

    assert result.exit_code == 0
    with open(test_val_file, 'r') as f:
        assert result.output == f.read() + '\n'

def test_upgrade(mocker):
    mock_subprocess_run(mocker)
    mock_insights_operator_and_crd_installed(mocker)
    mock_create_namespace(mocker)
    mocker.patch('kxicli.commands.install.read_secret', mock_read_secret)
    mocker.patch('kxicli.commands.install.copy_secret', mocked_copy_secret)
    mock_delete_crd(mocker)
    mocker.patch('kxicli.commands.assembly._get_assemblies_list', mock_list_assembly)
    mocker.patch('kxicli.commands.assembly._delete_assembly', mock_delete_assembly)
    mocker.patch('kxicli.commands.assembly._create_assembly', mock_create_assembly)

    test_asm_backup = os.path.dirname(__file__) + '/files/test-assembly-backup.yaml'
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
        result = runner.invoke(main.cli, ['install', 'upgrade', '--version', '1.2.3', '--assembly-backup-filepath', test_asm_backup], input=user_input)
        expected_output = f"""Upgrading KX Insights

Backing up assemblies
Persisted assembly definitions for ['{test_asm_name}'] to {test_asm_backup}

Tearing down assemblies
Deleting assembly {test_asm_name}
Are you sure you want to delete {test_asm_name} [y/N]: y

Uninstalling insights and operator

KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights

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
        ['helm', 'uninstall', 'insights'],
        ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator'],
        ['helm', 'install', '-f', '-', 'insights', 'kx-insights/kxi-operator', '--version', '1.2.3', '--namespace', 'kxi-operator'],
        ['helm', 'install', '-f', '-', 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
    ]
    assert subprocess_run_args == (True, values, True)
    assert delete_crd_params == ['assemblies.insights.kx.com','assemblyresources.insights.kx.com']
    assert insights_installed_flag == True
    assert operator_installed_flag ==True
    assert crd_exists_flag == True
    assert running_assembly[test_asm_name] == True
    os.remove(test_asm_backup)

def test_upgrade_skips_to_install_when_not_running(mocker):
    mock_subprocess_run(mocker)
    mock_create_namespace(mocker)
    mocker.patch('kxicli.commands.install.read_secret', mock_read_secret)
    mocker.patch('kxicli.commands.install.copy_secret', mocked_copy_secret)
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_false)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_false)

    runner = CliRunner()
    user_input = f"""y
"""
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'upgrade', '--version', '1.2.3'], input=user_input)
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
        ['helm', 'install', '-f', '-', 'insights', 'kx-insights/kxi-operator', '--version', '1.2.3', '--namespace', 'kxi-operator'],
        ['helm', 'install', '-f', '-', 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
    ]