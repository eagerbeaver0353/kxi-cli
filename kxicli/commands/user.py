from requests.exceptions import HTTPError
import click
import tabulate

from kxicli import options
from kxicli import common

from kxicli.commands.common import arg
from kxicli.resources.user import UserManager, RoleNotFoundException
from kxicli.cli_group import ProfileAwareGroup, cli

def get_user_manager(
    hostname: str,
    realm: str,
    admin_user: str,
    admin_password: str,
    timeout: int
):
    hostname = f'https://{common.sanitize_hostname(options.hostname.prompt(hostname, silent=True))}'
    realm = options.realm.prompt(realm, silent=True)
    admin_user = options.admin_username.prompt(admin_user, silent=True)
    admin_password = options.admin_password.prompt(admin_password, silent=True)
    return UserManager(hostname, admin_user, admin_password, realm, timeout)

@cli.group(cls=ProfileAwareGroup)
def user():
    """Insights user commands"""


@user.command()
@click.argument('username')
@click.option('--password', required=True, help='Password for user')
@click.option('--email', help='Email address for user')
@arg.temporary()
@arg.hostname()
@arg.realm()
@arg.admin_username()
@arg.admin_password()
@arg.timeout()
def create(
    username,
    password,
    email,
    temporary,
    hostname,
    realm,
    admin_username,
    admin_password,
    timeout
):
    """Create a user"""
    um = get_user_manager(hostname, realm, admin_username, admin_password, timeout)
    try:
        um.create_user(username, password, email, temporary=temporary)
        click.echo(f"Created user {username}")
    except HTTPError as e:
        common.handle_http_exception(e, "Creating user failed with")

@user.command()
@arg.hostname()
@arg.realm()
@arg.admin_username()
@arg.admin_password()
@arg.timeout()
def list(
    hostname,
    realm,
    admin_username,
    admin_password,
    timeout
):
    """List users"""
    um = get_user_manager(hostname, realm, admin_username, admin_password, timeout)
    keys_of_interest = ['username', 'email', 'enabled']
    try:
        user_info = um.list_users()
    except HTTPError as e:
        common.handle_http_exception(e, "Listing users failed with")
    users = []
    for user in user_info:
        users.append([user.get(key) for key in keys_of_interest])
    click.echo(tabulate.tabulate(users, headers=keys_of_interest))

@user.command()
@arg.hostname()
@arg.realm()
@arg.admin_username()
@arg.admin_password()
@arg.timeout()
def get_available_roles(
    hostname,
    realm,
    admin_username,
    admin_password,
    timeout
):
    """View the available roles"""
    um = get_user_manager(hostname, realm, admin_username, admin_password, timeout)
    keys_of_interest = ['name', 'description']
    try:
        role_info = um.get_roles()
    except HTTPError as e:
        common.handle_http_exception(e, "Getting roles failed with")
    roles = []
    for role in role_info:
        roles.append([role.get(key) for key in keys_of_interest])
    click.echo(tabulate.tabulate(roles, headers=keys_of_interest))

@user.command()
@click.argument("username")
@arg.hostname()
@arg.realm()
@arg.admin_username()
@arg.admin_password()
@arg.timeout()
def get_assigned_roles(
    username,
    hostname,
    realm,
    admin_username,
    admin_password,
    timeout
):
    """View the assigned roles for a user"""
    um = get_user_manager(hostname, realm, admin_username, admin_password, timeout)
    keys_of_interest = ['name', 'description']
    try:
        role_info = um.get_assigned_roles(username)
    except HTTPError as e:
        common.handle_http_exception(e, "Getting roles for user failed with")
    roles = []
    for role in role_info:
        roles.append([role.get(key) for key in keys_of_interest])
    click.echo(tabulate.tabulate(roles, headers=keys_of_interest))

@user.command()
@click.argument("username")
@click.option("--password", help="New password for the user")
@arg.temporary()
@arg.hostname()
@arg.realm()
@arg.admin_username()
@arg.admin_password()
@arg.timeout()
def reset_password(
    username,
    password,
    temporary,
    hostname,
    realm,
    admin_username,
    admin_password,
    timeout
):
    """Reset a user's password"""
    um = get_user_manager(hostname, realm, admin_username, admin_password, timeout)
    try:
        um.reset_password(username, password, temporary)
        click.echo(f"Successfully reset password for user {username}")
    except HTTPError as e:
        common.handle_http_exception(e, "Resetting user password failed with")

@user.command()
@click.argument("username")
@click.option("--roles", required=True, help="Comma separated list of roles")
@arg.hostname()
@arg.realm()
@arg.admin_username()
@arg.admin_password()
@arg.timeout()
def assign_roles(
    username,
    roles,
    hostname,
    realm,
    admin_username,
    admin_password,
    timeout
):
    """Assign roles to a user"""
    um = get_user_manager(hostname, realm, admin_username, admin_password, timeout)
    # split on comma and trim the spaces
    roles = [role.strip() for role in roles.split(',')]
    try:
        um.assign_roles(username=username, roles=roles)
    except RoleNotFoundException as e:
        raise click.ClickException(f"Assigning roles failed, could not find role(s): {str(e)}")
    except HTTPError as e:
        common.handle_http_exception(e, "Assigning roles failed with")
    click.echo(f"Role(s) {roles} assigned to user {username}")

@user.command()
@click.argument("username")
@click.option("--roles", required=True, help="Comma separated list of roles")
@arg.hostname()
@arg.realm()
@arg.admin_username()
@arg.admin_password()
@arg.timeout()
def remove_roles(
    username,
    roles,
    hostname,
    realm,
    admin_username,
    admin_password,
    timeout
):
    """Remove roles from a user"""
    um = get_user_manager(hostname, realm, admin_username, admin_password, timeout)
    # split on comma and trim the spaces
    roles = [role.strip() for role in roles.split(',')]
    try:
        um.remove_roles(username=username, roles=roles)
    except RoleNotFoundException as e:
        raise click.ClickException(f"Removing roles failed, could not find role(s): {str(e)}")
    except HTTPError as e:
        common.handle_http_exception(e, "Removing roles failed with")
    click.echo(f"Role(s) {roles} removed from user {username}")

@user.command()
@click.argument("username")
@arg.hostname()
@arg.realm()
@arg.admin_username()
@arg.admin_password()
@arg.timeout()
@arg.force()
def delete(
    username,
    hostname,
    realm,
    admin_username,
    admin_password,
    timeout,
    force
):
    """Delete a user"""
    um = get_user_manager(hostname, realm, admin_username, admin_password, timeout)
    try:
        if force or click.confirm(f"Are you sure you want to delete {username}"):
            um.delete_user(username)
            click.echo(f"Deleted user {username}")
    except HTTPError as e:
        common.handle_http_exception(e, "Deleting user failed with")
