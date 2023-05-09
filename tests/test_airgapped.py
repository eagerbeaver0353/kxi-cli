from click.testing import CliRunner

from kxicli import main
import const as c
import utils
import test_install_e2e as e2e

base = ["install"]
cmd_setup = base + ["setup"]
cmd_run = base + ["run"]
cmd_upgrade = base + ["upgrade"]

def test_setup_adds_repo_if_passed(mocker):
    runner = CliRunner()
    # ensure that helm repo add is mocked to track arguments for assertion
    e2e.setup_mocks(mocker)
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

def test_tgz_only_calls_helm_upgrade(mocker):
    runner = CliRunner()
    e2e.upgrades_mocks(mocker)
    # ensure that secret validation checks pass
    utils.mock_validate_secret(mocker)
    e2e.mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    e2e.mock_get_operator_version(mocker)
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
        e2e.HelmCommandOperatorInstall(chart=c.operator_tgz, version="1.5.0"),
        e2e.HelmCommandInsightsInstall(chart=c.insights_tgz, version="1.5.0")
    ])


def test_expection_when_operator_not_in_same_dir(mocker):
    runner = CliRunner()
    e2e.upgrades_mocks(mocker)
    # ensure that secret validation checks pass
    utils.mock_validate_secret(mocker)
    e2e.mock_set_insights_operator_and_crd_installed_state(mocker, False, False, False)
    mocker.patch('subprocess.check_output', e2e.mocked_helm_list_returns_empty_json)
    extra_args = [
        "--version",    "1.5.0",
        "--filepath",   utils.test_val_file,
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
