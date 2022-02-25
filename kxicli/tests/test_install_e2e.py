"""This end 2 end test validates the inputs and outputs of the install command directly"""
import os
import kubernetes as k8s
import filecmp
from click.testing import CliRunner
from kxicli import main
from kxicli import common
from kxicli import config

test_host = 'test.internal-insights.kx.com'
test_chart_repo_name = 'internal-nexus-dev'
test_chart_repo_url = 'https://nexus.internal-insights.kx.com/repository/kx-helm-charts-dev'
test_image_repo = 'test-repo.internal-insights.kx.com'
test_user = 'user'
test_pass = 'password'

test_val_file = os.path.dirname(__file__) + '/files/test-values.yaml'
test_k8s_config = os.path.dirname(__file__) + '/files/test-kube-config'
test_lic_file = os.path.dirname(__file__) + '/files/test-license'
test_output_file = os.path.dirname(__file__) + '/files/output-values.yaml'
test_docker_config_json = os.path.dirname(__file__) + '/files/test-docker-config-json'

_, active_context = k8s.config.list_kube_config_contexts()
test_namespace = active_context['context']['namespace']
test_cluster = active_context['context']['cluster']

delete_crd_params = ()

# override where the command looks for the docker config json
# by default this is $HOME/.docker/config.json
main.install.docker_config_file_path = test_docker_config_json

def mocked_create_secret(namespace, name, secret_type, data=None, string_data=None):
    print(f'Secret {name} successfully created')

def mocked_helm_add_repo(repo, url, username, password):
    pass

def mocked_subprocess_run(base_command, check=True):
    global subprocess_run_command
    subprocess_run_command = base_command
    pass

def mocked_delete_crd(name):
    print(f'Deleting CRD {name}')
    global delete_crd_params
    delete_crd_params = (name)
    pass

def mocked_create_namespace(namespace):
    pass

def mocked_copy_secret(name, from_ns, to_ns):
    pass

def mocked_return_true(name):
    return True

def mocked_return_false(name):
    return False

def test_install_when_creating_secrets(mocker):
    mocker.patch('kxicli.commands.install.create_secret', mocked_create_secret)
    mocker.patch('kxicli.commands.install.helm_add_repo', mocked_helm_add_repo)
    mocker.patch('kxicli.commands.install.create_namespace', mocked_create_namespace)

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
Do you want to set a secret for the gui service account explicity [y/N]: n
Randomly generating client secret for gui and setting in values file, record this value for reuse during upgrade
Do you want to set a secret for the operator service account explicity [y/N]: n
Randomly generating client secret for operator and setting in values file, record this value for reuse during upgrade

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""

    assert result.exit_code == 0
    assert result.output == expected_output

def test_install_when_providing_secrets(mocker):
    mocker.patch('kxicli.commands.install.create_secret', mocked_create_secret)
    mocker.patch('kxicli.commands.install.helm_add_repo', mocked_helm_add_repo)
    mocker.patch('kxicli.commands.install.create_namespace', mocked_create_namespace)

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
Do you want to set a secret for the gui service account explicity [y/N]: y
Please enter the secret (input hidden): 
Do you want to set a secret for the operator service account explicity [y/N]: y
Please enter the secret (input hidden): 

Ingress
Do you want to provide a self-managed cert for the ingress [y/N]: n

KX Insights installation setup complete

Helm values file for installation saved in {test_output_file}

"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert filecmp.cmp(test_output_file, test_val_file)

def test_install_run_when_provided_file(mocker):
    mocker.patch('subprocess.run', mocked_subprocess_run)
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_true)
    mocker.patch('kxicli.common.crd_exists', mocked_return_true)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""n
{test_val_file}
"""
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3'], input=user_input)
        expected_output = f"""
No values file provided, do you want to generate one now [y/N]: n
Please enter the path to the values file for the install: {test_val_file}

kxi-operator already installed
Installing chart kx-insights/insights with values file from {test_val_file}
"""    
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == ['helm', 'install', '-f', test_val_file, 'insights', 'kx-insights/insights', '--version', '1.2.3']

def test_install_run_installs_operator(mocker):
    mocker.patch('subprocess.run', mocked_subprocess_run)
    mocker.patch('kxicli.commands.install.create_namespace', mocked_create_namespace)
    mocker.patch('kxicli.commands.install.copy_secret', mocked_copy_secret)    
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_false)
    mocker.patch('kxicli.common.crd_exists', mocked_return_false)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""n
{test_val_file}
y
"""
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3'], input=user_input)
        expected_output = f"""
No values file provided, do you want to generate one now [y/N]: n
Please enter the path to the values file for the install: {test_val_file}

kxi-operator not found. Do you want to install it? [y/N]: y
Installing chart kx-insights/kxi-operator with values file from {test_val_file}
Installing chart kx-insights/insights with values file from {test_val_file}
"""    
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == ['helm', 'install', '-f', test_val_file, 'insights', 'kx-insights/insights', '--version', '1.2.3']

def test_delete(mocker):
    mocker.patch('subprocess.run', mocked_subprocess_run)
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
    assert subprocess_run_command == ['helm','uninstall','insights']
    assert delete_crd_params == ()

def test_delete_specify_release(mocker):
    mocker.patch('subprocess.run', mocked_subprocess_run)
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
    assert subprocess_run_command == ['helm','uninstall','atestrelease']
    assert delete_crd_params == ()


def test_delete_prompts_to_remove_insights_operator_and_crd(mocker):
    mocker.patch('subprocess.run', mocked_subprocess_run)
    mocker.patch('kxicli.common.delete_crd', mocked_delete_crd)
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_true)
    mocker.patch('kxicli.common.crd_exists', mocked_return_true)
    global subprocess_run_command
    subprocess_run_command = ['']

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
    assert subprocess_run_command == ['']
    assert delete_crd_params == ()

def test_delete_removes_insights_and_operator(mocker):
    mocker.patch('subprocess.run', mocked_subprocess_run)
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_true)
    mocker.patch('kxicli.common.crd_exists', mocked_return_true)

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
    assert subprocess_run_command == ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator']
    assert delete_crd_params == ()


def test_delete_removes_insights_and_crd(mocker):
    mocker.patch('subprocess.run', mocked_subprocess_run)
    mocker.patch('kxicli.common.delete_crd', mocked_delete_crd)
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_true)
    mocker.patch('kxicli.common.crd_exists', mocked_return_true)

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
    assert subprocess_run_command == ['helm', 'uninstall', 'insights']
    assert delete_crd_params == ('assemblyresources.insights.kx.com')

def test_delete_removes_insights_operator_and_crd(mocker):
    mocker.patch('subprocess.run', mocked_subprocess_run)
    mocker.patch('kxicli.common.delete_crd', mocked_delete_crd)
    mocker.patch('kxicli.commands.install.insights_installed', mocked_return_true)
    mocker.patch('kxicli.commands.install.operator_installed', mocked_return_true)
    mocker.patch('kxicli.common.crd_exists', mocked_return_true)

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
    assert subprocess_run_command == ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator']
    assert delete_crd_params == ('assemblyresources.insights.kx.com')
