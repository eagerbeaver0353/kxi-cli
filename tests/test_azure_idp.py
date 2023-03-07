from typing import List
from unittest import mock
from click.testing import CliRunner
import pytest
from pytest_mock import MockerFixture
from kxicli import main
from kxicli.azure_ad import AppRegistration, Group, Web
from kxicli.resources.keycloak_definitions import format_idp_list, format_mapper_list, get_email_mapper_definition, \
   get_idp_definition, get_preferred_username_mapper_definition, get_role_mapper_definition


@pytest.fixture
def mock_azure_ad_client():
    """Azure AD Client Mock"""
    with mock.patch("kxicli.azure_ad.AzureADClient") as mocked:
        mocked.return_value.get_app_registrations = get_test_app_registrations
        mocked.return_value.get_azure_app_registration_by_name = lambda dn: next(
            (x for x in get_test_app_registrations() if x.display_name == dn), None)

        mocked.return_value.add_secret_to_app_registration.return_value = "Secret"

        mocked.return_value.get_azure_ad_group_by_name = lambda dn: next(
            (x for x in get_test_ad_groups() if x.display_name == dn), None)

        yield mocked


@pytest.fixture
def mock_keycloak_admin_client():
    """Keycloak Admin Client Mock"""
    with mock.patch("keycloak.keycloak_admin.KeycloakAdmin") as mocked:
        mocked.return_value.get_idps = get_test_idp_list

        mocked.return_value.get_idp_mappers = get_test_idp_mappers_for_alias
        mocked.return_value.get_realm_roles = get_test_realm_roles
        yield mocked


@pytest.mark.parametrize("app_reg_name, expected_group_membership_claim",
                         [("app_reg1", "SecurityGroup"),
                          ("app_reg2", "SecurityGroup"),
                          ("app_reg3", "All")])
def test_azure_idp_add(mocker: MockerFixture,
                       mock_keycloak_admin_client,
                       mock_azure_ad_client,
                       app_reg_name,
                       expected_group_membership_claim):

    azure_app_registration_name = app_reg_name
    azure_tenant_id = "fake-tenant-id"

    insights_hostname = 'https://fake.localhost.com/auth'
    keycloak_idp_realm = "insights"
    keycloak_idp_alias = 'testidp'
    keycloak_idp_display_name = 'AzureAD'

    runner = CliRunner()
    result = runner.invoke(
        main.cli, f"""azure idp add
                --azure-tenant-id {azure_tenant_id}
                --azure-app-registration-name {azure_app_registration_name}
                --hostname {insights_hostname}
                --keycloak-idp-realm {keycloak_idp_realm}
                --keycloak-admin-username admin-usr
                --keycloak-admin-password admin-pwd
                --keycloak-idp-alias {keycloak_idp_alias}
                --keycloak-idp-display-name {keycloak_idp_display_name}""")

    assert result.exit_code == 0, result.output

    # Assert keycloak IdP and mappers were created
    mock_keycloak_admin_client.return_value.create_idp.assert_called_once_with(
        get_idp_definition(keycloak_idp_alias, keycloak_idp_display_name,
                           "appId", "Secret", azure_tenant_id)
    )

    mock_keycloak_admin_client.return_value.add_mapper_to_idp.assert_any_call(
        keycloak_idp_alias, get_email_mapper_definition(keycloak_idp_alias)
    )

    mock_keycloak_admin_client.return_value.add_mapper_to_idp.assert_any_call(
        keycloak_idp_alias, get_preferred_username_mapper_definition(
            keycloak_idp_alias)
    )

    # Assert App Registration was patched with proper GroupMembership and Redirect Uri
    mock_azure_ad_client.return_value.add_secret_to_app_registration.assert_called_once()

    expectedAppRegistration = create_app_registration(azure_app_registration_name,
                                                      expected_group_membership_claim, [f"{insights_hostname}/auth/realms/{keycloak_idp_realm}/broker/{keycloak_idp_alias}/endpoint"])

    mock_azure_ad_client.return_value.patch_app_registration.assert_called_once_with(
        expectedAppRegistration)

    # Assert CLI result


def test_azure_idp_add__groupmembershipclaim_all(
        mocker: MockerFixture, mock_keycloak_admin_client, mock_azure_ad_client):

    azure_app_registration_name = "app_reg3"
    azure_tenant_id = "fake-tenant-id"

    insights_hostname = 'https://fake.localhost.com/auth'
    keycloak_idp_realm = "insights"
    keycloak_idp_alias = 'testidp'
    keycloak_idp_display_name = 'AzureAD'

    runner = CliRunner()
    result = runner.invoke(
        main.cli, f"""azure idp add
                --azure-tenant-id {azure_tenant_id}
                --azure-app-registration-name {azure_app_registration_name}
                --hostname {insights_hostname}
                --keycloak-idp-realm {keycloak_idp_realm}
                --keycloak-admin-username admin-usr
                --keycloak-admin-password admin-pwd
                --keycloak-idp-alias {keycloak_idp_alias}
                --keycloak-idp-display-name {keycloak_idp_display_name}""")

    # Assert CLI result
    assert result.exit_code == 0, result.output

    # Assert keycloak IdP and mappers were created
    mock_keycloak_admin_client.return_value.create_idp.assert_called_once_with(
        get_idp_definition(keycloak_idp_alias, keycloak_idp_display_name,
                           "appId", "Secret", azure_tenant_id)
    )

    mock_keycloak_admin_client.return_value.add_mapper_to_idp.assert_any_call(
        keycloak_idp_alias, get_email_mapper_definition(keycloak_idp_alias)
    )

    mock_keycloak_admin_client.return_value.add_mapper_to_idp.assert_any_call(
        keycloak_idp_alias, get_preferred_username_mapper_definition(
            keycloak_idp_alias)
    )

    # Assert App Registration was patched with proper GroupMembership and Redirect Uri
    mock_azure_ad_client.return_value.add_secret_to_app_registration.assert_called_once()

    expectedAppRegistration = create_app_registration(azure_app_registration_name,
                                                      "All", [f"{insights_hostname}/auth/realms/{keycloak_idp_realm}/broker/{keycloak_idp_alias}/endpoint"])

    mock_azure_ad_client.return_value.patch_app_registration.assert_called_once_with(
        expectedAppRegistration)
    


def test_azure_idp_add__idp_already_exists(
        mocker: MockerFixture, mock_keycloak_admin_client, mock_azure_ad_client):

    azure_app_registration_name = "app_reg1"
    azure_tenant_id = "fake-tenant-id"

    keycloak_host_name = 'https://fake.localhost.com/auth'
    keycloak_idp_realm = "insights"
    keycloak_idp_alias = 'existingidp1'
    keycloak_idp_display_name = 'AzureAD'

    runner = CliRunner()
    result = runner.invoke(
        main.cli, f"""azure idp add
                --azure-tenant-id {azure_tenant_id}
                --azure-app-registration-name {azure_app_registration_name}
                --hostname {keycloak_host_name}
                --keycloak-idp-realm {keycloak_idp_realm}
                --keycloak-admin-username admin-usr
                --keycloak-admin-password admin-pwd
                --keycloak-idp-alias {keycloak_idp_alias}
                --keycloak-idp-display-name {keycloak_idp_display_name}""")

    # Assert CLI result
    assert result.exit_code == 1, result.output

    # Assert keycloak IdP and mappers were created
    assert not mock_keycloak_admin_client.return_value.create_idp.called
    assert f"IdP with alias {keycloak_idp_alias} already exists in keycloak realm." in result.output


def test_azure_idp_add__appregistration_not_found(
        mocker: MockerFixture, mock_keycloak_admin_client, mock_azure_ad_client):

    azure_app_registration_name = "not_existing"
    azure_tenant_id = "fake-tenant-id"

    keycloak_host_name = 'https://fake.localhost.com/auth'
    keycloak_idp_realm = "insights"
    keycloak_idp_alias = 'testidp'
    keycloak_idp_display_name = 'AzureAD'

    runner = CliRunner()
    result = runner.invoke(
        main.cli, f"""azure idp add
                --azure-tenant-id {azure_tenant_id}
                --azure-app-registration-name {azure_app_registration_name}
                --hostname {keycloak_host_name}
                --keycloak-idp-realm {keycloak_idp_realm}
                --keycloak-admin-username admin-usr
                --keycloak-admin-password admin-pwd
                --keycloak-idp-alias {keycloak_idp_alias}
                --keycloak-idp-display-name {keycloak_idp_display_name}""")
    # Assert CLI result
    assert result.exit_code == 1, result.output

    # Assert keycloak IdP and mappers were created
    assert not mock_keycloak_admin_client.return_value.create_idp.called
    assert f"Could not find app registration" in result.output


def test_azure_idp_list__returns_formatted_output(mocker: MockerFixture,
                                                  mock_keycloak_admin_client, mock_azure_ad_client):

    keycloak_host_name = 'https://fake.localhost.com/auth'
    keycloak_idp_realm = "insights"

    runner = CliRunner()
    result = runner.invoke(
        main.cli, f"""azure idp list
            --hostname {keycloak_host_name}
            --keycloak-idp-realm {keycloak_idp_realm}
            --keycloak-admin-username admin-usr
            --keycloak-admin-password admin-pwd""")
    assert format_idp_list(get_test_idp_list()) in result.output
    
    # Assert CLI result
    assert result.exit_code == 0, result.output


def test_azure_idp_mapper_add(mocker: MockerFixture,
                              mock_keycloak_admin_client, mock_azure_ad_client):

    azure_ad_group_name = "group1"
    azure_ad_group = next((x for x in get_test_ad_groups()
                          if x.display_name == azure_ad_group_name), None)
    azure_tenant_id = "fake-tenant-id"

    keycloak_host_name = 'https://fake.localhost.com/auth'
    keycloak_idp_realm = "insights"
    keycloak_idp_alias = 'existingidp1'
    keycloak_idp_mapper_name = 'mapper'
    keycloak_idp_mapper_roles = 'role1,role3,notexistingrole'

    runner = CliRunner()
    result = runner.invoke(
        main.cli, f"""azure idp mapper add
                --azure-tenant-id {azure_tenant_id}
                --azure-ad-group-name {azure_ad_group_name}
                --hostname {keycloak_host_name}
                --keycloak-idp-realm {keycloak_idp_realm}
                --keycloak-admin-username admin-usr
                --keycloak-admin-password admin-pwd
                --keycloak-idp-alias {keycloak_idp_alias}
                --keycloak-idp-mapper-name {keycloak_idp_mapper_name}
                --keycloak-idp-mapper-roles {keycloak_idp_mapper_roles}""")

    mock_keycloak_admin_client.return_value.add_mapper_to_idp.assert_called_once_with(
        keycloak_idp_alias, get_role_mapper_definition(
            "mapper - role3", keycloak_idp_alias, "role3", azure_ad_group.id)
    )

    assert f"Skipped 'mapper - role1' mapper because it already exists in '{keycloak_idp_alias}' IdP" in result.output
    assert f"Skipped 'mapper - notexistingrole' mapper because role 'notexistingrole' does not exists in {keycloak_idp_realm} realm" in result.output

    # Assert CLI result
    assert result.exit_code == 0, result.output


def test_azure_idp_mapper_add__idp_does_not_exists(mocker: MockerFixture,
                                                   mock_keycloak_admin_client, mock_azure_ad_client):

    azure_ad_group_name = "group1"
    azure_tenant_id = "fake-tenant-id"

    keycloak_host_name = 'https://fake.localhost.com/auth'
    keycloak_idp_realm = "insights"
    keycloak_idp_alias = 'notexisting'
    keycloak_idp_mapper_name = 'mapper'
    keycloak_idp_mapper_roles = 'roles'

    runner = CliRunner()
    result = runner.invoke(
        main.cli, f"""azure idp mapper add
                --azure-tenant-id {azure_tenant_id}
                --azure-ad-group-name {azure_ad_group_name}
                --hostname {keycloak_host_name}
                --keycloak-idp-realm {keycloak_idp_realm}
                --keycloak-admin-username admin-usr
                --keycloak-admin-password admin-pwd
                --keycloak-idp-alias {keycloak_idp_alias}
                --keycloak-idp-mapper-name {keycloak_idp_mapper_name}
                --keycloak-idp-mapper-roles {keycloak_idp_mapper_roles}""")

    assert f"IdP with alias {keycloak_idp_alias} does not exists in keycloak realm." in result.output

    # Assert CLI result
    assert result.exit_code == 1, result.output


def test_azure_idp_mapper_add__group_does_not_exists(mocker: MockerFixture,
                                                     mock_keycloak_admin_client, mock_azure_ad_client):

    azure_ad_group_name = "notexisting"
    azure_tenant_id = "fake-tenant-id"

    keycloak_host_name = 'https://fake.localhost.com/auth'
    keycloak_idp_realm = "insights"
    keycloak_idp_alias = 'existingidp1'
    keycloak_idp_mapper_name = 'mapper'
    keycloak_idp_mapper_roles = 'roles'

    runner = CliRunner()
    result = runner.invoke(
        main.cli, f"""azure idp mapper add
                --azure-tenant-id {azure_tenant_id}
                --azure-ad-group-name {azure_ad_group_name}
                --hostname {keycloak_host_name}
                --keycloak-idp-realm {keycloak_idp_realm}
                --keycloak-admin-username admin-usr
                --keycloak-admin-password admin-pwd
                --keycloak-idp-alias {keycloak_idp_alias}
                --keycloak-idp-mapper-name {keycloak_idp_mapper_name}
                --keycloak-idp-mapper-roles {keycloak_idp_mapper_roles}""")

    assert f"Could not find AD group '{azure_ad_group_name}'" in result.output

    # Assert CLI result
    assert result.exit_code == 1, result.output


def test_azure_idp_mapper_list(mocker: MockerFixture,
                               mock_keycloak_admin_client, mock_azure_ad_client):

    keycloak_host_name = 'https://fake.localhost.com/auth'
    keycloak_idp_realm = "insights"
    keycloak_idp_alias = 'existingidp1'

    runner = CliRunner()
    result = runner.invoke(
        main.cli, f"""azure idp mapper list
                --hostname {keycloak_host_name}
                --keycloak-idp-realm {keycloak_idp_realm}
                --keycloak-admin-username admin-usr
                --keycloak-admin-password admin-pwd
                --keycloak-idp-alias {keycloak_idp_alias}""")

    expectedMappers = [x["name"]
                       for x in get_test_idp_mappers_for_alias(keycloak_idp_alias)]
    assert format_mapper_list(expectedMappers) in result.output

    # Assert CLI result
    assert result.exit_code == 0, result.output


def test_azure_idp_mapper_list__idp_does_not_exists(mocker: MockerFixture,
                                                    mock_keycloak_admin_client, mock_azure_ad_client):

    keycloak_host_name = 'https://fake.localhost.com/auth'
    keycloak_idp_realm = "insights"
    keycloak_idp_alias = 'notexisting'

    runner = CliRunner()
    result = runner.invoke(
        main.cli, f"""azure idp mapper list
                --hostname {keycloak_host_name}
                --keycloak-idp-realm {keycloak_idp_realm}
                --keycloak-admin-username admin-usr
                --keycloak-admin-password admin-pwd
                --keycloak-idp-alias {keycloak_idp_alias}""")

    assert f"IdP with alias {keycloak_idp_alias} does not exists in keycloak realm." in result.output
    # Assert CLI result
    assert result.exit_code == 1, result.output


def create_app_registration(display_name: str, group_membership_claims: str, redirectUris: List[str]) -> AppRegistration:
    return AppRegistration(
        id="id",
        app_id="appId",
        display_name=display_name,
        group_membership_claims=group_membership_claims,
        web=Web(
            home_page_url="https://fake.localhost.com/homePage",
            logout_url="https://fake.localhost.com/logout",
            redirect_uris=redirectUris
        )
    )


def get_test_app_registrations() -> List[AppRegistration]:
    return [
        create_app_registration("app_reg1", None, []),
        create_app_registration("app_reg2", "SecurityGroup", []),
        create_app_registration("app_reg3", "All", []),
        create_app_registration("app_reg4", "SecurityGroup", [""])
    ]


def get_test_ad_groups() -> List[Group]:
    return [
        Group("id1", "group1"),
        Group("id2", "group2")
    ]


def get_test_idp_list():
    return [
        {
            "alias": "existingidp1",
            "displayName": "Test AD",
            "config": {
                "clientId": "existingidp1-client-id"
            }
        },
        {
            "alias": "existingidp2",
            "displayName": "Test AD",
            "config": {
                "clientId": "existingidp1-client-id"
            }
        }
    ]


def get_test_idp_mappers_for_alias(alias: str):
    return next((x["mappers"] for x in get_test_idp_mappers() if x["alias"] == alias), [])


def get_test_idp_mappers():
    return [
        {
            "alias": "existingidp1",
            "mappers": [
                {
                    "name": "mapper - role1"
                },
                {
                    "name": "mapper - role2"
                }
            ]
        }
    ]


def get_test_realm_roles():
    return [
        {
            "name": "role1"
        },
        {
            "name": "role2"
        },
        {
            "name": "role3"
        },
        {
            "name": "role4"
        }
    ]
