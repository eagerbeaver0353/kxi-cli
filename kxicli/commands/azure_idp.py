import copy
import os
from typing import List
import click

from kxicli import azure_ad
from keycloak import keycloak_admin
from kxicli import common
from kxicli.cli_group import ProfileAwareGroup

from azure.identity import DefaultAzureCredential
from kxicli.commands.install import install
from functools import wraps, partial

from kxicli.resources.keycloak_definitions import format_idp_list, format_mapper_list, get_email_mapper_definition, \
   get_idp_definition, get_preferred_username_mapper_definition, get_role_mapper_definition

arg_azure_tenant_id = partial(
    click.option, '--azure-tenant-id', help="Azure Tenant ID where the operations should point to",
    type=click.STRING, required=True
)

arg_azure_app_registration_name = partial(
    click.option, '--azure-app-registration-name', help="Name of the azure app registration to be used",
    type=click.STRING, required=True
)

arg_azure_ad_group_name = partial(
    click.option, '--azure-ad-group-name', help="Azure AD group name",
    type=click.STRING, required=True
)

arg_azure_enable_interactive_login = partial(
    click.option, '--azure-enable-interactive-login/--azure-disable-interactive-login', help="Switches interactive login for azure. Default is enabled.",
    type=click.BOOL, default = True
)

arg_hostname = partial(
    click.option, '--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'),
    type=click.STRING, required=True
)

arg_keycloak_admin_realm = partial(
    click.option, '--keycloak-admin-realm', default="master", help="KeyCloak admin realm",
    type=click.STRING
)

arg_keycloak_admin_username = partial(
    click.option, '--keycloak-admin-username', help="KeyCloak admin username", envvar='KEYCLOAK_USER',
    type=click.STRING
)

arg_keycloak_admin_password = partial(
    click.option, '--keycloak-admin-password', help="KeyCloak admin password", envvar='KEYCLOAK_PASSWORD',
    type=click.STRING
)

arg_keycloak_admin_clientid = partial(
    click.option, '--keycloak-admin-clientid', default="admin-cli", help="KeyCloak admin client",
    type=click.STRING
)

arg_keycloak_idp_realm = partial(
    click.option, '--keycloak-idp-realm', help="Realm where the IdP operations should point to", default=lambda: common.get_default_val('realm'),
    type=click.STRING
)

arg_keycloak_idp_alias = partial(
    click.option, '--keycloak-idp-alias', help="Identity Provider's alias", default="aad-idp",
    type=click.STRING
)

arg_keycloak_idp_display_name = partial(
    click.option, '--keycloak-idp-display-name', help="Identity Provider's display name", default="Azure AD",
    type=click.STRING
)

arg_keycloak_idp_mapper_name = partial(
    click.option, '--keycloak-idp-mapper-name', help="Mapper name of the IdP",
    type=click.STRING, required=True
)

arg_keycloak_idp_mapper_roles = partial(
    click.option, '--keycloak-idp-mapper-roles', help="Roles to add/remove to the mapper",
    type=click.STRING, required=True
)


def log_exception(func=None, *, handle):
    if not func:
        return partial(log_exception, handle=handle)

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except handle as e:
            raise click.ClickException(str(e))
    return wrapper


@install.group(cls=ProfileAwareGroup)
def idp():
    """Azure Identity Provider commands"""


@idp.group(cls=ProfileAwareGroup)
def mapper():
    """Identity Provider mapper commands"""


@idp.command(name="add")
@arg_azure_tenant_id()
@arg_azure_app_registration_name()
@arg_azure_enable_interactive_login()
@arg_hostname()
@arg_keycloak_admin_realm()
@arg_keycloak_admin_username()
@arg_keycloak_admin_password()
@arg_keycloak_admin_clientid()
@arg_keycloak_idp_realm()
@arg_keycloak_idp_alias()
@arg_keycloak_idp_display_name()
@log_exception(handle=(Exception))
def idp_add(azure_tenant_id: str,
            azure_app_registration_name: str,
            azure_enable_interactive_login: bool,
            hostname: str,
            keycloak_admin_realm: str,
            keycloak_admin_username: str,
            keycloak_admin_password: str,
            keycloak_admin_clientid: str,
            keycloak_idp_realm: str,
            keycloak_idp_alias: str,
            keycloak_idp_display_name: str
            ):
    """Add an Azure Identity Provider to a Keycloak realm"""

    keycloak_hostname = f"{hostname}/auth/"

    keycloak_client = create_authenticated_keycloak_client(
        keycloak_hostname,
        keycloak_admin_realm,
        keycloak_admin_username,
        keycloak_admin_password,
        keycloak_admin_clientid,
        keycloak_idp_realm)

    if keycloak_idp_exists(keycloak_client, keycloak_idp_alias):
        raise click.Abort(
            f'IdP with alias {keycloak_idp_alias} already exists in keycloak realm.')

    azure_client = get_azure_ad_client(
        use_interactive_login=azure_enable_interactive_login,
        tenant_id=azure_tenant_id)

    click.secho(
        f'Trying to get {azure_app_registration_name} app registration from {azure_tenant_id} tenant.')

    app_registration = azure_client.get_azure_app_registration_by_name(
        azure_app_registration_name)

    if app_registration is None:
        print_available_azure_app_registrations(azure_client)
        raise click.Abort(
            f"Could not find app registration {azure_app_registration_name}")

    secret_display_name = f"{keycloak_hostname}{keycloak_idp_realm}/{keycloak_idp_alias}"
    secret = azure_client.add_secret_to_app_registration(
        app_registration, secret_display_name)
    click.secho(f'Created secret with {secret_display_name} name.', bold=True)

    create_keycloak_idp(azure_tenant_id,
                        keycloak_idp_realm,
                        keycloak_idp_alias,
                        keycloak_idp_display_name,
                        keycloak_client,
                        app_registration,
                        secret)

    app_registration_copy = copy.deepcopy(app_registration)

    idp_redirect_uri = f"{keycloak_hostname}realms/{keycloak_idp_realm}/broker/{keycloak_idp_alias}/endpoint"
    if idp_redirect_uri not in app_registration.web.redirect_uris:
        app_registration_copy.web.redirect_uris.append(idp_redirect_uri)

    if app_registration.group_membership_claims not in ["SecurityGroup", "All"]:
        app_registration_copy.group_membership_claims = "SecurityGroup"

    if app_registration_copy != app_registration:
        click.secho("Updating app registration")
        azure_client.patch_app_registration(app_registration_copy)


@idp.command(name="list")
@arg_hostname()
@arg_keycloak_admin_realm()
@arg_keycloak_admin_username()
@arg_keycloak_admin_password()
@arg_keycloak_admin_clientid()
@arg_keycloak_idp_realm()
@log_exception(handle=(Exception))
def idp_list(hostname: str,
             keycloak_admin_realm: str,
             keycloak_admin_username: str,
             keycloak_admin_password: str,
             keycloak_admin_clientid: str,
             keycloak_idp_realm: str
             ):
    """List the Azure Identity Providers of a Keycloak realm"""

    keycloak_hostname = f"{hostname}/auth/"

    keycloak_client = create_authenticated_keycloak_client(
        keycloak_hostname,
        keycloak_admin_realm,
        keycloak_admin_username,
        keycloak_admin_password,
        keycloak_admin_clientid,
        keycloak_idp_realm)

    click.secho(format_idp_list(keycloak_client.get_idps()))


@mapper.command("add")
@arg_azure_tenant_id()
@arg_azure_ad_group_name()
@arg_azure_enable_interactive_login()
@arg_hostname()
@arg_keycloak_admin_realm()
@arg_keycloak_admin_username()
@arg_keycloak_admin_password()
@arg_keycloak_admin_clientid()
@arg_keycloak_idp_realm()
@arg_keycloak_idp_alias()
@arg_keycloak_idp_mapper_name()
@arg_keycloak_idp_mapper_roles()
@log_exception(handle=(Exception))
def mapper_add(azure_tenant_id: str,
               azure_ad_group_name: str,
               azure_enable_interactive_login: bool,
               hostname: str,
               keycloak_admin_realm: str,
               keycloak_admin_username: str,
               keycloak_admin_password: str,
               keycloak_admin_clientid: str,
               keycloak_idp_realm: str,
               keycloak_idp_alias: str,
               keycloak_idp_mapper_name: str,
               keycloak_idp_mapper_roles: str
               ):
    """Add a mapper to an Identity Provider"""

    keycloak_hostname = f"{hostname}/auth/"

    keycloak_client = create_authenticated_keycloak_client(
        keycloak_hostname,
        keycloak_admin_realm,
        keycloak_admin_username,
        keycloak_admin_password,
        keycloak_admin_clientid,
        keycloak_idp_realm)

    raise_if_keycloak_idp_does_not_exists(keycloak_client, keycloak_idp_alias)

    azure_client = get_azure_ad_client(
        use_interactive_login=azure_enable_interactive_login,
        tenant_id=azure_tenant_id)

    group = azure_client.get_azure_ad_group_by_name(azure_ad_group_name)

    if group is None:
        raise click.Abort(f"Could not find AD group '{azure_ad_group_name}'")

    existing_mappers = [x["name"]
                        for x in keycloak_client.get_idp_mappers(keycloak_idp_alias)]
    existing_roles = [x["name"] for x in keycloak_client.get_realm_roles()]

    for role in keycloak_idp_mapper_roles.split(','):
        new_mapper = f"{keycloak_idp_mapper_name} - {role}"

        if new_mapper in existing_mappers:
            click.secho(
                f"Skipped '{new_mapper}' mapper because it already exists in '{keycloak_idp_alias}' IdP", fg="yellow")
            continue

        if role not in existing_roles:
            click.secho(
                f"Skipped '{new_mapper}' mapper because role '{role}' does not exists in {keycloak_idp_realm} realm", fg="yellow")
            continue

        keycloak_client.add_mapper_to_idp(keycloak_idp_alias,
                                          get_role_mapper_definition(new_mapper, keycloak_idp_alias, role, group.id))

        click.secho(
            f"Created {new_mapper} in {keycloak_idp_alias} IdP", bold=True)


@mapper.command("list")
@arg_hostname()
@arg_keycloak_admin_realm()
@arg_keycloak_admin_username()
@arg_keycloak_admin_password()
@arg_keycloak_admin_clientid()
@arg_keycloak_idp_realm()
@arg_keycloak_idp_alias()
@log_exception(handle=(Exception))
def mapper_list(hostname: str,
                keycloak_admin_realm: str,
                keycloak_admin_username: str,
                keycloak_admin_password: str,
                keycloak_admin_clientid: str,
                keycloak_idp_realm: str,
                keycloak_idp_alias: str
                ):
    """List the mappers of an Identity Provider"""

    keycloak_hostname = f"{hostname}/auth/"

    keycloak_client = create_authenticated_keycloak_client(
        keycloak_hostname,
        keycloak_admin_realm,
        keycloak_admin_username,
        keycloak_admin_password,
        keycloak_admin_clientid,
        keycloak_idp_realm)

    raise_if_keycloak_idp_does_not_exists(keycloak_client, keycloak_idp_alias)

    existing_mappers = [x["name"]
                        for x in keycloak_client.get_idp_mappers(keycloak_idp_alias)]
    existing_mappers.sort(key=str.casefold)

    click.secho("\n")
    click.secho(format_mapper_list(existing_mappers))


def raise_if_keycloak_idp_does_not_exists(keycloak_client, keycloak_idp_alias):
    if not keycloak_idp_exists(keycloak_client, keycloak_idp_alias):
        raise click.Abort(
            f'IdP with alias {keycloak_idp_alias} does not exists in keycloak realm.')


def create_keycloak_idp(azure_tenant_id, keycloak_idp_realm, keycloak_idp_alias, keycloak_idp_display_name, keycloak_client, app_registration, secret):
    keycloak_client.create_idp(get_idp_definition(
        keycloak_idp_alias, keycloak_idp_display_name, app_registration.app_id, secret, azure_tenant_id))
    click.secho(
        f'Created {keycloak_idp_alias} IdP in {keycloak_idp_realm} realm.')

    keycloak_client.add_mapper_to_idp(
        keycloak_idp_alias, get_email_mapper_definition(keycloak_idp_alias))
    click.secho(
        f'Added Email mapper to {keycloak_idp_alias} IdP in {keycloak_idp_realm} realm.', bold=True)

    keycloak_client.add_mapper_to_idp(
        keycloak_idp_alias, get_preferred_username_mapper_definition(keycloak_idp_alias))
    click.secho(
        f'Added Preferred username mapper to {keycloak_idp_alias} IdP in {keycloak_idp_realm} realm.', bold=True)


def create_authenticated_keycloak_client(keycloak_hostname, keycloak_admin_realm, keycloak_admin_username, keycloak_admin_password, keycloak_admin_clientid, keycloak_idp_realm):

    keycloak_client = keycloak_admin.KeycloakAdmin(server_url=keycloak_hostname,
                                                   username=keycloak_admin_username,
                                                   password=keycloak_admin_password,
                                                   realm_name=keycloak_admin_realm,
                                                   client_id=keycloak_admin_clientid,
                                                   verify=True)

    keycloak_client.realm_name = keycloak_idp_realm
    click.secho(
        f'Successfully authenticated to {keycloak_hostname}, switching to {keycloak_idp_realm} realm')

    return keycloak_client


def keycloak_idp_exists(keycloak_client: str, keycloak_idp_alias: str) -> bool:
    idp = [x for x in keycloak_client.get_idps() if x['alias'] ==
           keycloak_idp_alias]

    return len(idp)

def print_available_azure_app_registrations(azure_client):
    registrations = [
        f"    {x.display_name}" for x in azure_client.get_app_registrations()]
    registrations.sort(key=str.casefold)

    click.secho("Available app registrations:")
    print(*registrations, sep='\n', )


def get_azure_ad_client(use_interactive_login: bool, tenant_id: str) -> azure_ad.AzureADClient:
    return azure_ad.AzureADClient(credential=DefaultAzureCredential(
        exclude_cli_credential = use_interactive_login,
        exclude_environment_credential = use_interactive_login,
        exclude_managed_identity_credential = use_interactive_login,
        # According to the documentation of DefaultCredential, managed_identity_client_id:
        # "The client ID of a user-assigned managed identity. Defaults to the value of the environment variable AZURE_CLIENT_ID, if any."
        # However, after testing if we don't set this here, it picks a random identity.
        managed_identity_client_id = os.environ.get('AZURE_CLIENT_ID', ""),
        exclude_powershell_credential = True,
        exclude_visual_studio_code_credential = True,
        exclude_shared_token_cache_credential = True,
        exclude_interactive_browser_credential = not use_interactive_login,
        interactive_browser_tenant_id=tenant_id
    ))
