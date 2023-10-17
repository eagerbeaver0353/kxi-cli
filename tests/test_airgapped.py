from click.testing import CliRunner

from kxicli import main
import const as c
import utils
import test_install_e2e as e2e

base = ["install"]
cmd_setup = base + ["setup"]
cmd_run = base + ["run"]
cmd_upgrade = base + ["upgrade"]
cmd_rollback = base + ["rollback"]

def test_setup_adds_repo_if_passed(mocker, k8s):
    runner = CliRunner()
    # ensure that helm repo add is mocked to track arguments for assertion
    e2e.setup_mocks(mocker, k8s)
    # ensure that secret validation checks pass
    utils.mock_validate_secret(mocker)
    extra_args = [
        "--chart-repo-name",        c.test_chart_repo_name,
        "--chart-repo-url",         c.test_chart_repo_url,
        "--chart-repo-username",    c.test_user
    ]
    # input password because this can't be passed as a command line parameter
    # it must either be a response to a prompt or in the ~/.insights/cli-config file.
    # must be entered twice because passwords are checked for typos by matching them.
    with runner.isolated_filesystem(), e2e.temp_config_file():
        runner.invoke(main.cli, cmd_setup+extra_args, input=f"{c.test_pass}\n{c.test_pass}\n")

    # assert that helm repo add is called with the parameters that were passed
    assert e2e.helm_add_repo_params == (c.test_chart_repo_name, c.test_chart_repo_url, c.test_user, c.test_pass)

def test_tgz_only_calls_helm_upgrade(mocker, k8s):
    runner = CliRunner()
    e2e.upgrades_mocks(mocker, k8s)
    # ensure that secret validation checks pass
    utils.mock_validate_secret(mocker)
    e2e.mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    e2e.mock_get_operator_version(mocker)
    e2e.mock_get_management_version(mocker)
    e2e.mock_copy_secret(mocker, k8s)
    extra_args = [
        "--version",    "1.5.0",
        "--filepath",   utils.test_val_file,
        c.insights_tgz
    ]

    # run both 'run' and 'upgrade' and capture the helm commands they call
    with runner.isolated_filesystem():
        runner.invoke(main.cli, cmd_run+extra_args)

    e2e.mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    with runner.isolated_filesystem():
        runner.invoke(main.cli, cmd_upgrade+extra_args)

    # ensure that 'helm repo update' isn't called
    # and that the tgz paths are referenced in the helm commands
    e2e.check_subprocess_run_commands([
        e2e.HelmCommandOperatorInstall(chart=c.operator_tgz, version="1.5.0"),
        e2e.HelmCommandInsightsInstall(chart=c.insights_tgz, version="1.5.0"),
        e2e.HelmCommandManagementInstall(management_chart=c.management_tgz),
        e2e.HelmCommandOperatorInstall(chart=c.operator_tgz, version="1.5.0"),
        e2e.HelmCommandInsightsInstall(chart=c.insights_tgz, version="1.5.0")
    ])


def test_expection_when_operator_not_in_same_dir(mocker, k8s):
    runner = CliRunner()
    e2e.upgrades_mocks(mocker, k8s)
    # ensure that secret validation checks pass
    utils.mock_validate_secret(mocker)
    e2e.mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    mocker.patch('subprocess.check_output', e2e.mocked_helm_list_returns_empty_json)
    extra_args = [
        "--version",    "1.5.0",
        "-f",   utils.test_val_file,
        c.insights_tgz
    ]

    with runner.isolated_filesystem():
        res = runner.invoke(main.cli, cmd_run+extra_args)

    assert res.exit_code == 1
    assert "Compatible version of operator not found" in res.output

    with runner.isolated_filesystem():
        res = runner.invoke(main.cli, cmd_upgrade+extra_args)

    assert res.exit_code == 1
    assert "Compatible version of operator not found" in res.output


def test_tgz_only_calls_helm_rollback(mocker, k8s):
    runner = CliRunner()
    e2e.mock_helm_list_history_same_operator(mocker)
    e2e.upgrades_mocks(mocker, k8s)
    # ensure that secret validation checks pass
    e2e.mock_helm_list_history(mocker)
    e2e.upgrades_mocks(mocker, k8s)
    e2e.mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    e2e.mock_get_operator_version(mocker)
    e2e.mock_get_management_version(mocker)
    utils.mock_validate_secret(mocker)
    utils.mock_kube_crd_api(k8s, create=e2e.mocked_create_crd)
    utils.mock_helm_env(mocker)
    utils.mock_helm_fetch(mocker)
    extra_args = [
        "--operator-revision", "1",
        "--operator-chart",    c.operator_tgz_123,
        "--namespace", c.test_namespace,
        "--assembly-backup-filepath",   e2e.test_asm_backup
    ]
    user_input = f"""y
    y
"""
    # run both 'run' and 'upgrade' and capture the helm commands they call
    with runner.isolated_filesystem():
        res = runner.invoke(main.cli, cmd_rollback+extra_args,  input=user_input)

    expected_output = f"""Rolling Insights back to version 1.2.3 and revision 1.
Rolling operator back to version 1.2.3 and revision 1.
Proceed? [y/N]: y

Backing up assemblies
Persisted assembly definitions for ['basic-assembly'] to {e2e.test_asm_backup}

Tearing down assemblies
Assembly data will be persisted and state will be recovered post-rollback
Tearing down assembly basic-assembly
Are you sure you want to teardown basic-assembly [y/N]:     y
Waiting for assembly to be torn down
Rollback kxi-operator complete for version 1.2.3
Using image.pullSecret from embedded default values: kxi-nexus-pull-secret
Reading CRD data from {utils.test_helm_repo_cache}/kxi-operator-1.2.3.tgz
Replacing CRD assemblies.insights.kx.com
Replacing CRD assemblyresources.insights.kx.com
Reading upgrade data from {utils.test_helm_repo_cache}/insights-1.2.1.tgz

Rolling back Insights
Rollback kdb Insights Enterprise complete for version 1.2.3

Reapplying assemblies
Submitting assembly from {e2e.test_asm_backup}
Submitting assembly basic-assembly
Custom assembly resource basic-assembly created!
"""
    assert expected_output == res.output
    assert res.exit_code == 0



def test_tgz_only_calls_helm_rollback_fail(mocker, k8s):
    runner = CliRunner()
    e2e.mock_helm_list_history_same_operator(mocker)
    e2e.upgrades_mocks(mocker, k8s)
    # ensure that secret validation checks pass
    e2e.mock_helm_list_histor_broken(mocker)
    e2e.upgrades_mocks(mocker, k8s)
    e2e.mock_set_insights_operator_and_crd_installed_state(mocker, True, True, True)
    e2e.mock_get_operator_version(mocker)
    e2e.mock_get_management_version(mocker)
    utils.mock_validate_secret(mocker)
    utils.mock_kube_crd_api(k8s, create=e2e.mocked_create_crd, delete=e2e.mocked_delete_crd)
    utils.mock_helm_env(mocker)
    utils.mock_helm_fetch(mocker)
    extra_args = [
        "--operator-revision", "1",
        "--operator-chart",    c.operator_tgz_123,
        "-n", c.test_namespace,
        "--assembly-backup-filepath",   e2e.test_asm_backup
    ]
    user_input = f"""y
    y
"""
    # run both 'run' and 'upgrade' and capture the helm commands they call
    with runner.isolated_filesystem():
        res = runner.invoke(main.cli, cmd_rollback+extra_args,  input=user_input)
    expected_output = f"""Rolling Insights back to version 2.2.3 and revision 1.
Rolling operator back to version 2.2.3 and revision 1.
Proceed? [y/N]: y
Error: Mismatch on the operator chart version 1.2.3 and the operator revision 1 version 2.2.3\n"""

    assert res.exit_code == 1
    assert expected_output == res.output

