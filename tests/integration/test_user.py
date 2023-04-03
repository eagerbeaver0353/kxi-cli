
import pytest
import twill
from click.testing import CliRunner

from kxicli import config
from kxicli import main

TEST_USER = "ci-user"
TEST_PASSWORD = "0neT1meAccess!"

# Fixtures

@pytest.fixture()
def remove_user():
    runner = CliRunner()
    runner.invoke(main.cli, ["user", "delete", TEST_USER, "--force"])

@pytest.fixture()
def create_user(remove_user):
    runner = CliRunner()
    runner.invoke(main.cli, ["user", "create", TEST_USER, "--password", TEST_PASSWORD])

# Tests
def test_user_create(remove_user):
    runner = CliRunner()
    result = runner.invoke(main.cli, ["user", "create", TEST_USER, "--password", TEST_PASSWORD])

    # Check that creating user works without error
    assert result.exit_code == 0
    assert TEST_USER in result.output

    # Check that running a second time fails with a conflict
    result = runner.invoke(main.cli, ["user", "create", TEST_USER, "--password", TEST_PASSWORD])
    assert result.exit_code == 1
    assert "Error: Creating user failed with 409 Conflict (User exists with same username)" in result.output

def test_user_list(remove_user):
    runner = CliRunner()

    # check that the user isn't in the list output before it's created
    result = runner.invoke(main.cli, ["user", "list"])
    assert result.exit_code == 0
    assert TEST_USER not in result.output

    # check that the user is in the list after it's created
    runner.invoke(main.cli, ["user", "create", TEST_USER, "--password", TEST_PASSWORD])
    result = runner.invoke(main.cli, ["user", "list"])
    assert result.exit_code == 0
    assert TEST_USER in result.output

def test_role_assignment_and_removal_happy_path(create_user):
    runner = CliRunner()

    single_role = "insights.client.create"
    multi_roles = ["insights.role.viewer", "insights.role.reporter"]

    result = runner.invoke(main.cli, ["user", "get-assigned-roles", TEST_USER])

    # check the user only has the default role when initially created
    assert result.exit_code == 0
    assert 'default-roles-insights' in result.output
    assert single_role not in result.output
    assert multi_roles[0] not in result.output
    assert multi_roles[1] not in result.output

    # assign a single role to the user and check it's in the output
    result = runner.invoke(main.cli, ["user", "assign-roles", TEST_USER, "--roles", single_role])
    assert result.exit_code == 0

    result = runner.invoke(main.cli, ["user", "get-assigned-roles", TEST_USER])
    assert result.exit_code == 0
    assert single_role in result.output

    # assign multiple roles and check they're in the output
    result = runner.invoke(main.cli, ["user", "assign-roles", TEST_USER, "--roles", ", ".join(multi_roles)])
    assert result.exit_code == 0

    result = runner.invoke(main.cli, ["user", "get-assigned-roles", TEST_USER])
    assert result.exit_code == 0
    assert multi_roles[0] in result.output
    assert multi_roles[1] in result.output

    # remove a single role and check it's not in the output
    result = runner.invoke(main.cli, ["user", "remove-roles", TEST_USER, "--roles", single_role])
    assert result.exit_code == 0

    result = runner.invoke(main.cli, ["user", "get-assigned-roles", TEST_USER])
    assert result.exit_code == 0
    assert single_role not in result.output

    # assign multiple roles and check they're in the output
    result = runner.invoke(main.cli, ["user", "remove-roles", TEST_USER, "--roles", ", ".join(multi_roles)])
    assert result.exit_code == 0

    result = runner.invoke(main.cli, ["user", "get-assigned-roles", TEST_USER])
    assert result.exit_code == 0
    assert multi_roles[0] not in result.output
    assert multi_roles[1] not in result.output

def test_role_assignment_and_removal_fails_with_invalid_role(create_user):
    runner = CliRunner()

    valid_role = "insights.client.create"
    invalid_role = "delete_everything"
    multi_roles = [valid_role, invalid_role]

    # check that assignment failed and the invalid role is in the output
    result = runner.invoke(main.cli, ["user", "assign-roles", TEST_USER, "--roles", ", ".join(multi_roles)])
    assert result.exit_code == 1
    assert invalid_role in result.output

    # check that neither role was assigned
    result = runner.invoke(main.cli, ["user", "get-assigned-roles", TEST_USER])
    assert valid_role not in result.output
    assert invalid_role not in result.output

    # check that removal failed
    result = runner.invoke(main.cli, ["user", "remove-roles", TEST_USER, "--roles", ", ".join(multi_roles)])
    assert result.exit_code == 1
    assert invalid_role in result.output

def test_get_available_roles():
    runner = CliRunner()
    result = runner.invoke(main.cli, ["user", "get-available-roles"])
    assert result.exit_code == 0
    assert "insights." in result.output

def test_user_delete_with_force(create_user):
    runner = CliRunner()

    # check that the user is in the list output before it's deletion
    result = runner.invoke(main.cli, ["user", "list"])
    assert result.exit_code == 0
    assert TEST_USER in result.output

    # check that the user is removed after deletion
    runner.invoke(main.cli, ["user", "delete", TEST_USER, "--force"])
    result = runner.invoke(main.cli, ["user", "list"])
    assert result.exit_code == 0
    assert TEST_USER not in result.output

def test_reset_password(create_user):
    runner = CliRunner()

    new_password = "F@stData12345!"
    result = runner.invoke(main.cli, ["user", "reset-password", TEST_USER, "--password", new_password])

    assert result.exit_code == 0

    config.load_config('default')
    host = config.config.get(config.config.default_section, 'hostname')

    # confirm that the original password fails
    # fill out username and password and submit
    # (use twill.commands.showforms() to view values when running interactive)
    twill.commands.go(host)
    twill.commands.form_value("1", "username", TEST_USER)
    twill.commands.form_value("1", "password", TEST_PASSWORD)
    twill.commands.submit("0")
    twill.commands.code(200)
    twill.commands.title('Sign in to kdb Insights Enterprise')

    # confirm that the new password works
    twill.commands.go(host)
    twill.commands.form_value("1", "username", TEST_USER)
    twill.commands.form_value("1", "password", new_password)
    twill.commands.submit("0")
    twill.commands.code(200)
    twill.commands.title('kdb Insights Enterprise')
