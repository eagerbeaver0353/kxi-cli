"""This end 2 end test validates the inputs and outputs of the install command directly"""
import copy
import filecmp
import os
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from tempfile import mkdtemp

import yaml, json
from click.testing import CliRunner

from kxicli import common
from kxicli import main
from kxicli import options
from kxicli import phrases
from kxicli.resources import secret
from kxicli.commands.assembly import CONFIG_ANNOTATION
from utils import mock_kube_secret_api, return_none, return_true, raise_not_found, \
    test_val_file, mock_validate_secret, mock_kube_crd_api, mock_helm_env, mock_helm_fetch, \
    test_helm_repo_cache
from cli_io import cli_input, cli_output
from const import test_namespace,  test_chart_repo_name, test_chart_repo_url, \
    test_user, test_pass, test_docker_config_json, test_cert, test_key, test_ingress_cert_secret

common.config.config_file = os.path.dirname(__file__) + '/files/test-cli-config'
common.config.load_config("default")

GET_ASSEMBLIES_LIST_FUNC='kxicli.commands.assembly._get_assemblies_list'
DELETE_ASSEMBLIES_FUNC='kxicli.commands.assembly._delete_assembly'
TEST_VALUES_FILE="a test values file"

test_auth_url = 'http://keycloak.keycloak.svc.cluster.local/auth/'
test_chart = 'kx-insights/insights'
test_operator_chart = 'kx-insights/kxi-operator'
test_install_secret = 'test-install-secret'

test_k8s_config = str(Path(__file__).parent / 'files' / 'test-kube-config')
test_cli_config_static = str(Path(__file__).parent / 'files' / 'test-cli-config')
expected_test_output_file = str(Path(__file__).parent / 'files' / 'output-values.yaml')
test_output_file_lic_env_var = str(Path(__file__).parent / 'files' / 'output-values-license-as-env-var.yaml')
test_output_file_lic_on_demand = str(Path(__file__).parent / 'files' / 'output-values-license-on-demand.yaml')
test_output_file_manual_ingress = str(Path(__file__).parent / 'files' / 'output-values-manual-ingress-secret.yaml')
test_output_file_updated_hostname = str(Path(__file__).parent / 'files' / 'output-values-updated-hostname.yaml')
test_val_file_shared_keycloak = str(Path(__file__).parent / 'files' / 'test-values-shared-keycloak.yaml')
test_asm_file = str(Path(__file__).parent / 'files' / 'assembly-v1.yaml')
test_asm_file2 = str(Path(__file__).parent / 'files' / 'assembly2-v1.yaml')
test_asm_name = 'basic-assembly'  # As per contents of test_asm_file
test_asm_name2 = 'basic-assembly2'  # As per contents of test_asm_file2
test_asm_backup =  str(Path(__file__).parent / 'files' / 'test-assembly-backup.yaml')
test_crds = ['assemblies.insights.kx.com', 'assemblyresources.insights.kx.com']

with open(test_val_file, 'rb') as values_file:
    test_vals = yaml.full_load(values_file)

helm_add_repo_params = ()
delete_crd_params = []
delete_assembly_args = []
insights_installed_flag = True
operator_installed_flag = True
crd_exists_flag = True
running_assembly = {}
copy_secret_params = []

# override where the command looks for the docker config json
# by default this is $HOME/.docker/config.json
main.install.DOCKER_CONFIG_FILE_PATH = test_docker_config_json

# Tell cli that this is an interactive session
options._is_interactive_session = return_true

@contextmanager
def temp_test_output_file(prefix: str = 'kxicli-e2e-', file_name='output-values.yaml'):
    dir_name: str = str()
    inited: bool = False
    try:
        dir_name = mkdtemp(prefix=prefix)
        inited = True
        output_file_name = str(Path(dir_name).joinpath(file_name))
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


def mocked_read_namespaced_secret_return_values(namespace, name):
    res = secret.Secret(namespace, name, main.install.SECRET_TYPE_OPAQUE)
    res = main.install.populate_install_secret(res, {'values': test_vals})
    return res.get_body()


def mocked_helm_add_repo(repo, url, username, password):
    global helm_add_repo_params
    helm_add_repo_params = (repo, url, username, password)
    pass


def mocked_helm_list_returns_empty_json(base_command):
    return '[]'


def mocked_empty_list():
    return []


def mocked_helm_repo_list():
    return [{'name':test_chart_repo_name, 'url': test_chart_repo_url}]


def mock_empty_helm_repo_list(mocker):
    mocker.patch('kxicli.commands.install.helm_repo_list', mocked_empty_list)


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

def mock_delete_crd(mocker):
    global delete_crd_params
    delete_crd_params = []
    global crd_exists_flag
    crd_exists_flag = True
    mocker.patch('kxicli.common.delete_crd', mocked_delete_crd)

def mocked_copy_secret(name, from_ns, to_ns):
    global copy_secret_params
    copy_secret_params.append((name, from_ns, to_ns))


def mock_copy_secret(mocker):
    global copy_secret_params
    copy_secret_params = []
    mocker.patch('kxicli.commands.install.copy_secret', mocked_copy_secret)


def mocked_k8s_list_empty_config():
    return ([], {'context': ()})


def mocked_create_namespace(namespace):
    # Test function to mock
    pass


def mock_create_namespace(mocker):
    mocker.patch('kxicli.commands.install.create_namespace', mocked_create_namespace)


def mocked_get_operator_version(chart_repo_name, insights_version, operator_version):
    if operator_version:
        return operator_version
    else:
        return insights_version


def mock_get_operator_version(mocker):
    mocker.patch('kxicli.commands.install.get_operator_version', mocked_get_operator_version)

def mocked_helm_list_returns_valid_json(release, namespace):
    if operator_installed_flag and namespace == 'kxi-operator':
        return [{"name":"insights","namespace":"testNamespace","revision":"1","updated":"2022-02-23 10:39:53.7668809 +0000 UTC","status":"deployed","chart":"kxi-operator-1.2.0","app_version":"1.2.0"}]
    elif insights_installed_flag and namespace == test_namespace:
        return [{"name":"insights","namespace":"testNamespace","revision":"1","updated":"2022-02-23 10:39:53.7668809 +0000 UTC","status":"deployed","chart":"insights-1.2.1","app_version":"1.2.1"}]
    else:
        return []

def mocked_subprocess_run(base_command, check=True, input=None, text=None, capture_output=False):
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
    elif [base_command[i] for i in [0, 1, -2, -1]] == ['helm', 'upgrade', '--install', '--namespace', 'kxi-operator']:
        operator_installed_flag = True
    elif [base_command[i] for i in [0, 1, -2, -1]] == ['helm', 'upgrade', '--install', '--namespace', test_namespace]:
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
    mocker.patch('kxicli.commands.install.get_installed_charts', mocked_helm_list_returns_valid_json)


def mocked_insights_installed(release, namespace):
    return insights_installed_flag


def mocked_operator_installed(release):
    return operator_installed_flag


def mocked_crd_exists(name):
    return crd_exists_flag


def mock_secret_helm_add(mocker):
    mock_kube_secret_api(mocker, read=raise_not_found)
    mock_empty_helm_repo_list(mocker)
    helm_add_repo_params = ()
    mocker.patch('kxicli.commands.install.helm_add_repo', mocked_helm_add_repo)


def mock_list_assembly_none(namespace):
    return {'items': []}


def mock_list_assembly(namespace):
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)
    return {'items': [test_asm]}


def mock_list_assembly_multiple(namespace):
    with open(test_asm_file) as f:
        test_asm = yaml.safe_load(f)
    with open(test_asm_file2) as f:
        test_asm2 = yaml.safe_load(f)
    
    return {'items': [test_asm, test_asm2]}


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

def mock__delete_assembly(namespace, name, wait, force):
    global delete_assembly_args
    delete_assembly_args.append({'name':name, 'namespace':namespace})
    return True


def upgrades_mocks(mocker):
    mock_subprocess_run(mocker)
    mock_create_namespace(mocker)
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)
    mock_copy_secret(mocker)
    mock_delete_crd(mocker)
    mock_delete_assembly(mocker)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly)
    mocker.patch('kxicli.commands.assembly._create_assembly', mock_create_assembly)


def install_setup_output_check(mocker, test_cfg, expected_exit_code):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file]
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, expected_exit_code)


def run_cli(cmd, test_cfg, cli_config = None, output_file = None, expected_exit_code = 0):
    runner = CliRunner()
    with runner.isolated_filesystem():
        verb = cmd[1]
        user_input = cli_input(verb, **test_cfg)
        expected_output = cli_output(verb, cli_config, output_file, **test_cfg)
        result = runner.invoke(main.cli, cmd, input=user_input)

    assert result.exit_code == expected_exit_code
    assert result.output == expected_output


def test_install_setup_when_creating_secrets(mocker):
    install_setup_output_check(mocker, {}, 0)


def test_install_setup_when_using_existing_docker_creds(mocker):
    test_cfg = {
        'use_existing_creds': 'y'
    }
    install_setup_output_check(mocker, test_cfg, 0)

def test_install_setup_when_generating_random_passwords(mocker):
    test_cfg = {
        'provide_gui_secret': 'n',
        'provide_operator_secret': 'n'
    }
    install_setup_output_check(mocker, test_cfg, 0)

def test_install_setup_when_secret_exists_but_is_invalid(mocker):
    test_cfg = {
        'lic_sec_exists': True,
        'lic_sec_is_valid': False,
        'image_sec_exists': True,
        'image_sec_is_valid': False,
        'client_sec_exists': True,
        'client_sec_is_valid': False,
        'kc_secret_exists': True,
        'kc_secret_is_valid': False,
        'pg_secret_exists': True,
        'pg_secret_is_valid': False
    }
    mock_validate_secret(mocker, is_valid=False)
    install_setup_output_check(mocker, test_cfg, 0)


def test_install_setup_when_secrets_exist_and_are_valid(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    mock_validate_secret(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file]
        test_cfg = {
            'lic_sec_exists': True,
            'image_sec_exists': True,
            'client_sec_exists': True,
            'kc_secret_exists': True,
            'pg_secret_exists': True
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)

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


def test_install_setup_check_output_values_file(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file]
        run_cli(cmd, {}, test_cli_config, test_output_file, 0)
        assert compare_files(test_output_file, expected_test_output_file)


def test_install_setup_when_hostname_provided_from_command_line(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file, '--hostname', 'https://a-test-hostname.kx.com'] 
        test_cfg = {
            'hostname_check': False
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)
        assert compare_files(test_output_file, test_output_file_updated_hostname)


def test_install_setup_ingress_host_is_an_alias_for_hostname(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file, '--ingress-host', 'https://a-test-hostname.kx.com'] 
        test_cfg = {
            'hostname_check': False
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)
        assert compare_files(test_output_file, test_output_file_updated_hostname)

def test_install_setup_when_chart_repo_provided_from_command_line(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    test_repo_name='test-repo-command-line'
    test_repo_url='https://test-repo-command-line.kx.com/repository/kx-insights-charts'
    test_repo_username='test-repo-username-command-line'
    test_repo_password='test-repo-password-prompt'
 
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file, '--chart-repo-name', test_repo_name, '--chart-repo-url', test_repo_url, '--chart-repo-username', test_repo_username]
        test_cfg = {
            'chart_repo_name': None,
            'chart_repo_url': None,
            'chart_user': None,
            'chart_pass': test_repo_password
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)
        assert helm_add_repo_params == (test_repo_name, test_repo_url, test_repo_username, test_repo_password)



def test_install_setup_does_not_prompt_when_chart_repo_already_exists(mocker):
    mock_create_namespace(mocker)
    mock_kube_secret_api(mocker, read=raise_not_found)
    mocker.patch('kxicli.commands.install.helm_repo_list', mocked_helm_repo_list)
    helm_add_repo_params = ()
    mocker.patch('kxicli.commands.install.helm_add_repo', mocked_helm_add_repo)
 
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file, '--chart-repo-name', test_chart_repo_name]
        test_cfg = {
            'chart_repo_existing': test_chart_repo_name,
            'chart_repo_name': None,
            'chart_repo_url': None,
            'chart_user': None,
            'chart_pass': None
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)
        assert helm_add_repo_params == ()


def test_install_setup_when_ingress_cert_prompted(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file] 
        test_cfg = {
            'provide_ingress_cert': 'y'
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)
        assert compare_files(test_output_file, test_output_file_manual_ingress)


def test_install_setup_when_ingress_cert_secret_provided_on_command_line(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file, '--ingress-cert-secret', test_ingress_cert_secret] 
        test_cfg = {
            'provide_ingress_cert': None
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)
        assert compare_files(test_output_file, test_output_file_manual_ingress)


def test_install_setup_when_ingress_cert_provided_on_command_line(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_test_output_file(file_name='tls_crt') as test_cert_filepath, \
        temp_test_output_file(file_name='tls_key') as test_key_filepath, temp_config_file() as test_cli_config:
        shutil.copyfile(test_cert, test_cert_filepath)
        shutil.copyfile(test_key, test_key_filepath)
        cmd = ['install', 'setup', '--output-file', test_output_file, '--ingress-cert', test_cert_filepath, '--ingress-key', test_key_filepath] 
        test_cfg = {
            'provide_ingress_cert': 'y',
            'ingress_cert': test_cert_filepath,
            'ingress_key': test_key_filepath
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)
        assert compare_files(test_output_file, test_output_file_manual_ingress)


def test_install_setup_when_passed_license_env_var_in_command_line(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    mock_validate_secret(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file, '--license-as-env-var', 'True']
        test_cfg = {
            'lic_sec_exists': True,
            'image_sec_exists': True,
            'client_sec_exists': True,
            'kc_secret_exists': True,
            'pg_secret_exists': True
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)

        assert compare_files(test_output_file, test_output_file_lic_env_var)


def test_install_setup_when_passed_kc_license_filename(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config, temp_test_output_file(
            file_name='kc.lic') as test_kc_lic:
        with open(test_kc_lic, 'w') as f:
            f.write('This is a test kc license')
        cmd = ['install', 'setup', '--output-file', test_output_file]
        test_cfg = {
            'lic': test_kc_lic
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)

        assert compare_files(test_output_file, test_output_file_lic_on_demand)


def test_install_setup_when_providing_license_secret(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    mock_validate_secret(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        cmd = ['install', 'setup', '--output-file', test_output_file, '--license-secret', common.get_default_val('license.secret')]
        test_cfg = {
            'lic_sec_exists': True,
            'image_sec_exists': True,
            'client_sec_exists': True,
            'kc_secret_exists': True,
            'pg_secret_exists': True
        }
        mocker.patch('sys.argv', cmd)
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)
        assert compare_files(test_output_file, test_val_file)


def test_install_setup_overwrites_when_values_file_exists(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        with open(test_output_file, 'w') as f:
            f.write(TEST_VALUES_FILE)

        cmd = ['install', 'setup', '--output-file', test_output_file]
        test_cfg = {
            'values_exist': True,
            'overwrite_values': 'y'
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)

        assert compare_files(test_output_file, test_val_file)


def test_install_setup_creates_new_when_values_file_exists(mocker):
    mock_secret_helm_add(mocker)
    mock_create_namespace(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        with open(test_output_file, 'w') as f:
            f.write(TEST_VALUES_FILE)

        cmd = ['install', 'setup', '--output-file', test_output_file]
        test_cfg = {
            'values_exist': True,
            'overwrite_values': 'n',
            'output_file': test_output_file
        }

        runner = CliRunner()
        with runner.isolated_filesystem():
            user_input = cli_input(cmd[1], **test_cfg)
            result = runner.invoke(main.cli, cmd, input=user_input)
            expected_output = cli_output(cmd[1], test_cli_config, **test_cfg)
        
        assert result.exit_code == 0
        assert result.output == expected_output
        assert compare_files(f'{test_output_file}_new', test_val_file)
        with open(test_output_file, "r") as f:
            assert f.read() == TEST_VALUES_FILE # assert that the original file is unchanged


def test_install_run_when_provided_file(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, True, True)
    mock_create_namespace(mocker)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli,
            ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file],
            input='n'
        )
        expected_output = f"""{phrases.values_validating}

kxi-operator already installed with version kxi-operator-1.2.0
Do you want to install kxi-operator version 1.2.3? [Y/n]: n
Installing chart kx-insights/insights version 1.2.3 with values file from {test_val_file}
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm', 'upgrade', '--install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace',
         test_namespace]
    ]


def test_install_run_when_no_file_provided(mocker):
    mock_empty_helm_repo_list(mocker)
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)
    mock_subprocess_run(mocker)
    mocker.patch('subprocess.check_output', mocked_helm_list_returns_empty_json)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    mock_create_namespace(mocker)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
    with temp_test_output_file() as test_output_file, temp_config_file() as test_cli_config:
        with open(test_output_file, 'w') as f:
            f.write(TEST_VALUES_FILE)

        runner = CliRunner()
        with runner.isolated_filesystem():
            test_cfg = {
                'lic_sec_exists': True,
                'image_sec_exists': True,
                'client_sec_exists': True,
                'kc_secret_exists': True,
                'pg_secret_exists': True,
                'install_config_exists': True
            }
            user_input = f'{cli_input("setup", **test_cfg)}\nn'
            result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3'], input=user_input)

            expected_output = f"""{phrases.header_run}
{cli_output('setup', test_cli_config, 'values.yaml', **test_cfg)}{phrases.values_validating}

kxi-operator not found
Do you want to install kxi-operator version 1.2.3? [Y/n]: n
Installing chart internal-nexus-dev/insights version 1.2.3 with values file from values.yaml
"""

        assert result.exit_code == 0
        assert result.output == expected_output
        assert subprocess_run_command == [
            ['helm', 'repo', 'add', '--username', test_user, '--password', test_pass, test_chart_repo_name,
             test_chart_repo_url],
            ['helm', 'repo', 'update'],
            ['helm', 'upgrade', '--install', '-f', 'values.yaml', 'insights', test_chart_repo_name + '/insights', '--version',
             '1.2.3', '--namespace', test_namespace]
        ]


def test_install_run_when_provided_secret(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, True, True)
    mock_create_namespace(mocker)
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli,
            ['install', 'run', '--version', '1.2.3', '--install-config-secret', test_install_secret],
            input='n'
        )
        expected_output = f"""{phrases.values_validating}

kxi-operator already installed with version kxi-operator-1.2.0
Do you want to install kxi-operator version 1.2.3? [Y/n]: n
Installing chart kx-insights/insights version 1.2.3 with values from secret
"""
    with open(test_val_file, 'r') as values_file:
        values = str(values_file.read())
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm', 'upgrade', '--install', '-f', '-', 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
    ]
    assert subprocess_run_args == (True, values, True)


def test_install_run_when_provided_file_and_secret(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, True, True)
    mock_create_namespace(mocker)
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli,
            ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file,
                                          '--install-config-secret', test_install_secret],
            input='n'
        )
        expected_output = f"""{phrases.values_validating}

kxi-operator already installed with version kxi-operator-1.2.0
Do you want to install kxi-operator version 1.2.3? [Y/n]: n
Installing chart kx-insights/insights version 1.2.3 with values from secret and values file from {test_val_file}
"""
    with open(test_val_file, 'r') as values_file:
        values = str(values_file.read())
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm', 'upgrade', '--install', '-f', '-', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace',
         test_namespace]
    ]
    assert subprocess_run_args == (True, values, True)


def test_install_run_installs_operator(mocker):
    mock_subprocess_run(mocker)
    mock_create_namespace(mocker)
    mock_copy_secret(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
    global copy_secret_params
    copy_secret_params = []

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file],
                               input=user_input)
        expected_output = f"""{phrases.values_validating}

kxi-operator not found
Do you want to install kxi-operator version 1.2.3? [Y/n]: y
Installing chart kx-insights/kxi-operator version 1.2.3 with values file from {test_val_file}
Installing chart kx-insights/insights version 1.2.3 with values file from {test_val_file}
"""    
    assert result.exit_code == 0
    assert result.output == expected_output
    assert copy_secret_params == [('kxi-nexus-pull-secret', test_namespace, 'kxi-operator'),
                                  ('kxi-license', test_namespace, 'kxi-operator')]
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm', 'upgrade', '--install', '-f', test_val_file, 'insights', test_operator_chart, '--version', '1.2.3', '--namespace',
         'kxi-operator'],
        ['helm', 'upgrade', '--install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace',
         test_namespace]
    ]


def test_install_run_force_installs_operator(mocker):
    mock_subprocess_run(mocker)
    mock_create_namespace(mocker)
    mock_copy_secret(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
    global copy_secret_params
    copy_secret_params = []

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli,
                               ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file, '--force'])
        expected_output = f"""{phrases.values_validating}

kxi-operator not found
Installing chart kx-insights/kxi-operator version 1.2.3 with values file from {test_val_file}
Installing chart kx-insights/insights version 1.2.3 with values file from {test_val_file}
"""    
    assert result.exit_code == 0
    assert result.output == expected_output
    assert copy_secret_params == [('kxi-nexus-pull-secret', test_namespace, 'kxi-operator'),
                                  ('kxi-license', test_namespace, 'kxi-operator')]
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm', 'upgrade', '--install', '-f', test_val_file, 'insights', test_operator_chart, '--version', '1.2.3', '--namespace',
         'kxi-operator'],
        ['helm', 'upgrade', '--install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace',
         test_namespace]
    ]


def test_install_run_with_operator_version(mocker):
    mock_subprocess_run(mocker)
    mock_create_namespace(mocker)
    mock_copy_secret(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
    global copy_secret_params
    copy_secret_params = []

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli,
                               ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file, '--operator-version', '4.5.6'])
        expected_output = f"""{phrases.values_validating}

kxi-operator not found
Installing chart kx-insights/kxi-operator version 4.5.6 with values file from {test_val_file}
Installing chart kx-insights/insights version 1.2.3 with values file from {test_val_file}
"""    
    assert result.exit_code == 0
    assert result.output == expected_output
    assert copy_secret_params == [('kxi-nexus-pull-secret', test_namespace, 'kxi-operator'),
                                  ('kxi-license', test_namespace, 'kxi-operator')]
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm', 'upgrade', '--install', '-f', test_val_file, 'insights', test_operator_chart, '--version', '4.5.6', '--namespace',
         'kxi-operator'],
        ['helm', 'upgrade', '--install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace',
         test_namespace]
    ]


def test_install_run_installs_operator_with_modified_secrets(mocker):
    mock_subprocess_run(mocker)
    mock_create_namespace(mocker)
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)
    mock_copy_secret(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
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
        result = runner.invoke(main.cli,
                               ['install', 'run', '--version', '1.2.3', '--install-config-secret', test_install_secret],
                               input=user_input)
        expected_output = f"""{phrases.values_validating}

kxi-operator not found
Do you want to install kxi-operator version 1.2.3? [Y/n]: y
Installing chart kx-insights/kxi-operator version 1.2.3 with values from secret
Installing chart kx-insights/insights version 1.2.3 with values from secret
"""    
    assert result.exit_code == 0
    assert result.output == expected_output
    assert copy_secret_params == [('new-image-pull-secret', test_namespace, 'kxi-operator'),
                                  ('new-license-secret', test_namespace, 'kxi-operator')]
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm', 'upgrade', '--install', '-f', '-', 'insights', test_operator_chart, '--version', '1.2.3', '--namespace',
         'kxi-operator'],
        ['helm', 'upgrade', '--install', '-f', '-', 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
    ]
    assert subprocess_run_args == (True, yaml.dump(test_vals), True)
    test_vals = test_vals_backup


def test_install_run_when_no_context_set(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, True, True)
    mock_create_namespace(mocker)
    mock_get_operator_version(mocker)
    mocker.patch('kubernetes.config.list_kube_config_contexts', mocked_k8s_list_empty_config)
    mock_validate_secret(mocker)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        result = runner.invoke(main.cli,
            ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file],
            input='\nn'
        )
        expected_output = f"""
Please enter a namespace to run in [test]: 
{phrases.values_validating}

kxi-operator already installed with version kxi-operator-1.2.0
Do you want to install kxi-operator version 1.2.3? [Y/n]: n
Installing chart kx-insights/insights version 1.2.3 with values file from {test_val_file}
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm', 'upgrade', '--install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace', 'test']
    ]


def test_install_run_exits_when_already_installed(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    mock_create_namespace(mocker)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file], input ='n\n')
        expected_output = f"""{phrases.values_validating}
KX Insights is already installed with version insights-1.2.1. Would you like to upgrade to version 1.2.3? [y/N]: n
"""

    assert result.exit_code == 0
    assert result.output == expected_output


def test_delete(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, False, False)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly_multiple)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, mock__delete_assembly)
    
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
    assert subprocess_run_command == [['helm', 'uninstall', 'insights', '--namespace', test_namespace]]
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
    assert subprocess_run_command == [['helm', 'search', 'repo', test_chart_repo_name + '/insights']]


def test_delete_specify_release(mocker):
    global delete_assembly_args
    
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, False, False)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly_multiple)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, mock__delete_assembly)
    
    delete_assembly_args = []
    asms_array = [test_asm_name, test_asm_name2]
    
    
    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'delete', '--release', 'atestrelease'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release atestrelease in namespace {test_namespace}
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert len(delete_assembly_args) == len(asms_array)
    for deleted_asm in delete_assembly_args:
        assert deleted_asm['name'] in asms_array
    assert subprocess_run_command == [['helm', 'uninstall', 'atestrelease', '--namespace', test_namespace]]
    assert delete_crd_params == []

def test_delete_specific_release_no_assemblies(mocker):
    global delete_assembly_args

    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, False, False)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly_none)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, mock__delete_assembly)
    
    delete_assembly_args = []
    
    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'delete', '--release', 'atestrelease'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release atestrelease in namespace {test_namespace}
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert len(delete_assembly_args) == 0
    assert subprocess_run_command == [['helm', 'uninstall', 'atestrelease', '--namespace', test_namespace]]
    assert delete_crd_params == []

def test_delete_specific_release_one_assemblies(mocker):
    global delete_assembly_args

    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, False, False)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, mock__delete_assembly)
    
    delete_assembly_args = []
    asms_array = [test_asm_name]

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'delete', '--release', 'atestrelease'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release atestrelease in namespace {test_namespace}
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert len(delete_assembly_args) == len(asms_array)
    for deleted_asm in delete_assembly_args:
        assert deleted_asm['name'] in asms_array
    assert subprocess_run_command == [['helm', 'uninstall', 'atestrelease', '--namespace', test_namespace]]
    assert delete_crd_params == []


def test_delete_does_not_prompt_to_remove_operator_and_crd_when_insights_exists(mocker):
    """
    Tests if a user answers n to removing insights, the kxi exits withotu furterh prompts
    """
    global delete_assembly_args

    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly_multiple)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, mock__delete_assembly)
    
    delete_assembly_args = []
    
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
    assert len(delete_assembly_args) == 0
    assert subprocess_run_command == []
    assert delete_crd_params == []


def test_delete_removes_insights_and_operator(mocker):
    global delete_assembly_args

    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly_multiple)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, mock__delete_assembly)
    delete_assembly_args = []
    asms_array = [test_asm_name, test_asm_name2]

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, ['install', 'delete','--uninstall-operator'], input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace {test_namespace}
Uninstalling release insights in namespace kxi-operator
Deleting CRD assemblies.insights.kx.com
Deleting CRD assemblyresources.insights.kx.com
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert len(delete_assembly_args) == len(asms_array)
    for deleted_asm in delete_assembly_args:
        assert deleted_asm['name'] in asms_array
    assert subprocess_run_command == [
        ['helm', 'uninstall', 'insights', '--namespace', test_namespace],
        ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator']
    ]
    assert delete_crd_params == test_crds


def test_delete_removes_insights(mocker):
    global delete_assembly_args

    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly_multiple)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, mock__delete_assembly)
    
    delete_assembly_args = []
    asms_array = [test_asm_name, test_asm_name2]

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
    assert len(delete_assembly_args) == len(asms_array)
    for deleted_asm in delete_assembly_args:
        assert deleted_asm['name'] in asms_array
    assert subprocess_run_command == [['helm', 'uninstall', 'insights', '--namespace', test_namespace]]


def test_delete_force_removes_insights_operator_and_crd(mocker):
    global delete_assembly_args

    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly_multiple)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, mock__delete_assembly)
    
    delete_assembly_args = []
    asms_array = [test_asm_name, test_asm_name2]

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
    assert len(delete_assembly_args) == len(asms_array)
    for deleted_asm in delete_assembly_args:
        assert deleted_asm['name'] in asms_array
    assert subprocess_run_command == [
        ['helm', 'uninstall', 'insights', '--namespace', test_namespace],
        ['helm', 'uninstall', 'insights', '--namespace', 'kxi-operator']
    ]
    assert delete_crd_params == test_crds


def test_delete_from_given_namespace(mocker):
    mock_subprocess_run(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, False, False)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly_multiple)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, mock__delete_assembly)
    
    global delete_crd_params
    global delete_assembly_args
    
    delete_assembly_args = []
    delete_crd_params = []
    asms_array = [test_asm_name, test_asm_name2]

    cmd = ['install', 'delete', '--namespace', 'a_test_namespace']
    mocker.patch('sys.argv', cmd)

    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
"""
        result = runner.invoke(main.cli, cmd, input=user_input)
        expected_output = f"""
KX Insights is deployed. Do you want to uninstall? [y/N]: y
Uninstalling release insights in namespace a_test_namespace
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert len(delete_assembly_args) == len(asms_array)
    for deleted_asm in delete_assembly_args:
        assert deleted_asm['name'] in asms_array
    assert subprocess_run_command == [['helm', 'uninstall', 'insights', '--namespace', 'a_test_namespace']]
    assert delete_crd_params == []


def test_delete_when_insights_not_installed(mocker):
    mock_subprocess_run(mocker)
    mock_delete_crd(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, True, True)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly_multiple)
    mocker.patch(DELETE_ASSEMBLIES_FUNC, mock__delete_assembly)
    
    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""n
"""
        result = runner.invoke(main.cli, ['install', 'delete'], input=user_input)
        expected_output = f"""
KX Insights installation not found
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
        mocker.patch('kxicli.commands.install.deploy_keycloak', lambda: False)

        cmd = ['install', 'setup', '--keycloak-auth-url', test_auth_url, '--output-file', test_output_file]
        test_cfg = {
            'values_exist': True,
            'overwrite_values': 'y',
            'deploy_keycloak': False
        }
        run_cli(cmd, test_cfg, test_cli_config, test_output_file, 0)
        assert compare_files(test_output_file, test_val_file_shared_keycloak)


def test_get_values_returns_error_when_does_not_exist(mocker):
    mock = mocker.patch('kubernetes.client.CoreV1Api')
    mock.return_value.read_namespaced_secret = return_none

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'get-values'])

    assert result.exit_code == 0
    assert result.output == f"""Cannot find values secret {common.get_default_val('install.configSecret')}\n\n"""


def test_get_values_returns_decoded_secret(mocker):
    mock_kube_secret_api(mocker, read=mocked_read_namespaced_secret_return_values)
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'get-values'])

    assert result.exit_code == 0
    with open(test_val_file, 'r') as f:
        assert result.output == f.read() + '\n'


def test_upgrade(mocker):
    upgrades_mocks(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
    mock_helm_env(mocker)
    mock_helm_fetch(mocker)
    mock_kube_crd_api(mocker)
    if os.path.exists(test_asm_backup):
        os.remove(test_asm_backup)
    with open(test_asm_file) as f:
        file = yaml.safe_load(f)
        last_applied = file['metadata']['annotations'][CONFIG_ANNOTATION]
        test_asm_file_contents = json.loads(last_applied)
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
        result = runner.invoke(main.cli,
            ['install', 'upgrade', '--version', '1.2.3', '--install-config-secret',
                    test_install_secret, '--assembly-backup-filepath', test_asm_backup],
            input=user_input
        )
        expected_output = f"""Upgrading KX Insights
{phrases.values_validating}

kxi-operator already installed with version kxi-operator-1.2.0
Do you want to install kxi-operator version 1.2.3? [Y/n]: y
Reading CRD data from {test_helm_repo_cache}/kxi-operator-1.2.3.tgz

Backing up assemblies
Persisted assembly definitions for ['{test_asm_name}'] to {test_asm_backup}

Tearing down assemblies
Assembly data will be persisted and state will be recovered post-upgrade
Tearing down assembly {test_asm_name}
Are you sure you want to teardown {test_asm_name} [y/N]: y
Waiting for assembly to be torn down

Upgrading insights and operator
Installing chart kx-insights/kxi-operator version 1.2.3 with values from secret
Replacing CRD assemblies.insights.kx.com
Replacing CRD assemblyresources.insights.kx.com

KX Insights already installed with version insights-1.2.1
Installing chart kx-insights/insights version 1.2.3 with values from secret

Reapplying assemblies
Submitting assembly from {test_asm_backup}
Submitting assembly {test_asm_name}
Custom assembly resource {test_asm_name} created!

Upgrade to version 1.2.3 complete
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    with open(test_asm_backup) as f:
        expect = yaml.safe_load(f)
        assert expect == {'items': [test_asm_file_contents]}
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm', 'upgrade', '--install', '-f', '-', 'insights', test_operator_chart, '--version', '1.2.3', '--namespace',
         'kxi-operator'],
        ['helm', 'upgrade', '--install', '-f', '-', 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
    ]
    assert subprocess_run_args == (True, values, True)
    assert delete_crd_params == []
    assert insights_installed_flag == True
    assert operator_installed_flag == True
    assert crd_exists_flag == True
    assert running_assembly[test_asm_name] == True
    os.remove(test_asm_backup)


def test_upgrade_skips_to_install_when_not_running(mocker):
    upgrades_mocks(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
    runner = CliRunner()
    user_input = f"""y
"""
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli,
            ['install', 'upgrade', '--version', '1.2.3', '--install-config-secret', test_install_secret],
            input=user_input
        )
    expected_output = f"""Upgrading KX Insights
{phrases.values_validating}

kxi-operator not found
Do you want to install kxi-operator version 1.2.3? [Y/n]: y
KX Insights is not deployed. Skipping to install
Installing chart kx-insights/kxi-operator version 1.2.3 with values from secret
Installing chart kx-insights/insights version 1.2.3 with values from secret

Upgrade to version 1.2.3 complete
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm',  'upgrade', '--install', '-f', '-', 'insights', test_operator_chart, '--version', '1.2.3', '--namespace',
         'kxi-operator'],
        ['helm',  'upgrade', '--install', '-f', '-', 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
    ]


def test_upgrade_when_user_declines_to_teardown_assembly(mocker):
    upgrades_mocks(mocker)
    mocker.patch(GET_ASSEMBLIES_LIST_FUNC, mock_list_assembly_multiple)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    mock_validate_secret(mocker)
    mock_get_operator_version(mocker)
    mock_helm_env(mocker)
    mock_helm_fetch(mocker)

    if os.path.exists(test_asm_backup):
        os.remove(test_asm_backup)
    with open(test_asm_file) as f:
        file = yaml.safe_load(f)
        last_applied = file['metadata']['annotations'][CONFIG_ANNOTATION]
        test_asm_file_contents = json.loads(last_applied)
    
    with open(test_asm_file2) as f:
        file = yaml.safe_load(f)
        last_applied = file['metadata']['annotations'][CONFIG_ANNOTATION]
        test_asm_file_contents2 = json.loads(last_applied)

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli,
            ['install', 'upgrade', '--version', '1.2.3', '--filepath', test_val_file,
                '--assembly-backup-filepath', test_asm_backup],
            input='y\ny\nn\n'
        )
    expected_output = f"""Upgrading KX Insights
{phrases.values_validating}

kxi-operator already installed with version kxi-operator-1.2.0
Do you want to install kxi-operator version 1.2.3? [Y/n]: y
Reading CRD data from {test_helm_repo_cache}/kxi-operator-1.2.3.tgz

Backing up assemblies
Persisted assembly definitions for ['{test_asm_name}', '{test_asm_name + '2'}'] to {test_asm_backup}

Tearing down assemblies
Assembly data will be persisted and state will be recovered post-upgrade
Tearing down assembly {test_asm_name}
Are you sure you want to teardown {test_asm_name} [y/N]: y
Waiting for assembly to be torn down
Tearing down assembly {test_asm_name2}
Are you sure you want to teardown {test_asm_name2} [y/N]: n
Not tearing down assembly {test_asm_name2}

Reapplying assemblies
Submitting assembly from {test_asm_backup}
Submitting assembly {test_asm_name}
Custom assembly resource {test_asm_name} created!
Submitting assembly {test_asm_name2}
Custom assembly resource {test_asm_name2} created!
"""
    assert result.exit_code == 0
    with open(test_asm_backup) as f:
        expect = yaml.safe_load(f)
        assert expect == {'items':
            [
                test_asm_file_contents,
                test_asm_file_contents2
            ]
        }
    assert subprocess_run_command == []
    assert delete_crd_params == []
    assert insights_installed_flag == True
    assert operator_installed_flag == True
    assert crd_exists_flag == True
    assert running_assembly[test_asm_name] == True
    assert running_assembly[test_asm_name2] == True
    assert result.output == expected_output
    os.remove(test_asm_backup)


def test_upgrade_reapplies_assemblies_when_upgrade_fails(mocker):
    upgrades_mocks(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
    mock_helm_env(mocker)
    mock_helm_fetch(mocker)
    mock_kube_crd_api(mocker)
    if os.path.exists(test_asm_backup):
        os.remove(test_asm_backup)
    with open(test_asm_file) as f:
        file = yaml.safe_load(f)
        last_applied = file['metadata']['annotations'][CONFIG_ANNOTATION]
        test_asm_file_contents = json.loads(last_applied)
    with open(test_val_file, 'r') as values_file:
        values = str(values_file.read())
    mocker.patch('subprocess.run').side_effect = subprocess.CalledProcessError(1, ['helm', 'upgrade'])
    runner = CliRunner()
    with runner.isolated_filesystem():
        # these are responses to the various prompts
        user_input = f"""y
y
y
y
y
"""
        result = runner.invoke(main.cli,
            ['install', 'upgrade', '--version', '1.2.3', '--install-config-secret',
                    test_install_secret, '--assembly-backup-filepath', test_asm_backup],
            input=user_input
        )
        expected_output = f"""Upgrading KX Insights
{phrases.values_validating}

kxi-operator already installed with version kxi-operator-1.2.0
Do you want to install kxi-operator version 1.2.3? [Y/n]: y
Reading CRD data from {test_helm_repo_cache}/kxi-operator-1.2.3.tgz

Backing up assemblies
Persisted assembly definitions for ['{test_asm_name}'] to {test_asm_backup}

Tearing down assemblies
Assembly data will be persisted and state will be recovered post-upgrade
Tearing down assembly {test_asm_name}
Are you sure you want to teardown {test_asm_name} [y/N]: y
Waiting for assembly to be torn down

Upgrading insights and operator
error={phrases.upgrade_error}
Submitting assembly from {test_asm_backup}
Submitting assembly {test_asm_name}
Custom assembly resource {test_asm_name} created!
"""
    assert result.exit_code == 1
    assert result.output == expected_output
    with open(test_asm_backup) as f:
        expect = yaml.safe_load(f)
        assert expect == {'items': [test_asm_file_contents]}
    assert insights_installed_flag == True
    assert operator_installed_flag == True
    assert crd_exists_flag == True
    assert running_assembly[test_asm_name] == True
    os.remove(test_asm_backup)

def test_install_run_upgrades_when_already_installed(mocker):
    upgrades_mocks(mocker)
    mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    mock_create_namespace(mocker)
    mock_get_operator_version(mocker)
    mock_validate_secret(mocker)
    mock_kube_crd_api(mocker)
    mock_helm_env(mocker)
    mock_helm_fetch(mocker)
    test_asm_backup = common.get_default_val('assembly.backup.file')

    runner = CliRunner()
    user_input = f"""y
y
y
"""
    with runner.isolated_filesystem():
        result = runner.invoke(main.cli, ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file], input =user_input)
        expected_output = f"""{phrases.values_validating}
KX Insights is already installed with version insights-1.2.1. Would you like to upgrade to version 1.2.3? [y/N]: y
Upgrading KX Insights
{phrases.values_validating}

kxi-operator already installed with version kxi-operator-1.2.0
Do you want to install kxi-operator version 1.2.3? [Y/n]: y
Reading CRD data from {test_helm_repo_cache}/kxi-operator-1.2.3.tgz

Backing up assemblies
Persisted assembly definitions for ['{test_asm_name}'] to {test_asm_backup}

Tearing down assemblies
Assembly data will be persisted and state will be recovered post-upgrade
Tearing down assembly {test_asm_name}
Are you sure you want to teardown {test_asm_name} [y/N]: y
Waiting for assembly to be torn down

Upgrading insights and operator
Installing chart kx-insights/kxi-operator version 1.2.3 with values file from {test_val_file}
Replacing CRD assemblies.insights.kx.com
Replacing CRD assemblyresources.insights.kx.com

KX Insights already installed with version insights-1.2.1
Installing chart kx-insights/insights version 1.2.3 with values file from {test_val_file}

Reapplying assemblies
Submitting assembly from {test_asm_backup}
Submitting assembly {test_asm_name}
Custom assembly resource {test_asm_name} created!

Upgrade to version 1.2.3 complete
"""
    assert result.exit_code == 0
    assert result.output == expected_output
    assert subprocess_run_command == [
        ['helm', 'repo', 'update'],
        ['helm', 'upgrade', '--install', '-f', test_val_file, 'insights', test_operator_chart, '--version', '1.2.3', '--namespace', 'kxi-operator'],
        ['helm', 'upgrade', '--install', '-f', test_val_file, 'insights', test_chart, '--version', '1.2.3', '--namespace', test_namespace]
    ]
    assert insights_installed_flag == True
    assert operator_installed_flag ==True
    assert crd_exists_flag == True


def test_install_values_validated_on_run_and_upgrade(mocker):
    test_cfg = {
        'lic_sec_exists': False,
        'lic_sec_is_valid': False,
        'image_sec_exists': True,
        'image_sec_is_valid': False,
        'client_sec_exists': True,
        'client_sec_is_valid': False,
        'kc_secret_exists': True,
        'kc_secret_is_valid': False,
        'pg_secret_exists': True,
        'pg_secret_is_valid': False
    }
    mock_validate_secret(mocker, exists=False)
    cmd = ['install', 'upgrade', '--version', '1.2.3', '--filepath', test_val_file]
    run_cli(cmd, test_cfg, expected_exit_code = 1)
    cmd = ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file]
    run_cli(cmd, test_cfg, expected_exit_code = 1)

    mock_validate_secret(mocker, is_valid=False)
    test_cfg['lic_sec_exists'] = True
    cmd = ['install', 'upgrade', '--version', '1.2.3', '--filepath', test_val_file]
    run_cli(cmd, test_cfg, expected_exit_code = 1)
    cmd = ['install', 'run', '--version', '1.2.3', '--filepath', test_val_file]
    run_cli(cmd, test_cfg, expected_exit_code = 1)

