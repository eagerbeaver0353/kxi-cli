import os
import click
import secrets
import string
import pyk8s
import kxicli.common
from pathlib import Path

from functools import partial
from kxicli import config
from kxicli import phrases
from kxicli.common import get_default_val as default_val
from kxicli.common import get_help_text as help_text
from kxicli.common import key_install_outputFile, key_chart_repo_name, \
    key_image_repository, key_image_repository_user, key_image_repository_password, key_image_pullSecret, \
    key_ingress_cert_secret, key_ingress_certmanager_disabled, key_ingress_cert, key_ingress_key, \
    key_keycloak_secret, key_keycloak_admin_password, key_keycloak_management_password, \
    key_keycloak_postgresqlSecret, key_postgresql_postgres_password, key_postgresql_user_password, \
    key_keycloak_authURL, key_keycloak_realm, key_install_outputFile, \
    key_license_secret, key_license_envVar, key_license_filepath, \
    key_chart_repo_url, key_chart_repo_username, key_chart_repo_password, \
    key_client_cert_secret, key_gui_client_secret, key_operator_client_secret, \
    key_install_filepath, key_assembly_backup_file, \
    key_namespace, key_hostname, key_version, key_operator_version, \
    key_client_id, key_client_secret, key_admin_username, key_serviceaccount_id, key_serviceaccount_secret, \
    key_cache_file, key_auth_client
from kxicli.common import enter_password


def print_option_source(message, val, password, silent):
    if silent:
        return None
    if not password:
        message = message + f': {val}'
    # Write notice information to stderr
    click.echo(message, err=True)


def print_cmd_line_option(message, val, password, default, silent):
    try:
        if default() is None:
            print_option_source(message, val, password, silent)
    except TypeError:
        if default is None:
            print_option_source(message, val, password, silent)


def get_prompt_message(self, prompt_message):
    if prompt_message:
        return prompt_message
    elif self.prompt_message:
        return self.prompt_message


def interactive_prompt(prompt_message, password, default):
    if password:
        return enter_password(prompt_message)
    else:
        return click.prompt(prompt_message, default=default)


def prompt_error_message(self):
    error_message = 'Could not find expected option.'
    if self.click_option_args:
        error_message = error_message + f' Please set command line argument {self.click_option_args}'
        if self.config_name:
            error_message = error_message + f' or configuration value {self.config_name} in config file {config.config_file}'
    elif self.config_name:
        error_message = error_message + f' Please set configuration value {self.config_name} in config file {config.config_file}'

    return error_message


def generate_password():
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))


class Option():
    def __init__(self, *click_option_args , config_name=None, fallback=None, force=False, password=False,
                 prompt_message='', default_before_user_input=False, envvar = None, **click_option_kwargs):
        self._click_option_args = click_option_args
        self._click_option_kwargs = click_option_kwargs
        self._config_name = config_name
        self._fallback = fallback
        self._force = force
        self._envvar = envvar
        self._password = password
        self._prompt_message = prompt_message
        self._default_before_user_input = default_before_user_input

    @property
    def click_option_args(self):
        return self._click_option_args

    @property
    def click_option_kwargs(self):
        return self._click_option_kwargs

    @property
    def config_name(self):
        return self._config_name

    @property
    def fallback(self):
        return self._fallback

    @property
    def force(self):
        return self._force

    @property
    def envvar(self):
        return self._envvar

    @property
    def password(self):
        return self._password

    @property
    def prompt_message(self):
        return self._prompt_message

    @property
    def default_before_user_input(self):
        return self._default_before_user_input


    def prompt(self, cmd_line_value=None, **kwargs):
        """Get config value from various sources.

        Priority:
            - CLI
            - CONFIG file
            - (if default_over_user_input) DEFAULT value
            - (TTY) USER PROMPT
            - (if not default_over_user_input) DEFAULT value
            - FALLBACK value.

        Args:
            cmd_line_value: Command line argument value.

        Raises:
            click.ClickException: Raised when values cannot be determined.

        Returns:
            The config value.
        """
        prompt_message = get_prompt_message(self, kwargs.get('prompt_message'))
        silent =  kwargs.get('silent')
        default_fn = self.click_option_kwargs.get('default')
        default = default_fn() if default_fn else default_val(self.config_name)

        # cmd line arg
        if cmd_line_value is not None:
            val = cmd_line_value
            print_cmd_line_option(f'Using {self.config_name} from command line option', val,
                self.password, default_fn, silent)
        # config file
        elif config.config.has_option(config.config.default_section, self.config_name):
            val = config.config.get(config.config.default_section, self.config_name)
            print_option_source(f'Using {self.config_name} from config file {config.config_file}', val, self.password, silent)
        # When default has higher priority than user input.
        elif self.default_before_user_input and default:
            val = default
            print_option_source(f'Using {self.config_name} from dynamic default values', val, self.password, silent)
        # check if there's a tty and not explicitly no prompt
        elif prompt_message and kxicli.common.is_interactive_session() and not silent:
            val = interactive_prompt(prompt_message, self.password, default)
        # embedded default values
        elif self.config_name in kxicli.common.DEFAULT_VALUES:
            val = default
            print_option_source(f'Using {self.config_name} from embedded default values', val, self.password, silent)
        elif self.fallback:
            val = self.fallback()
        else:
            raise click.ClickException(prompt_error_message(self))

        return val


    def decorator(self, click_option_args=None):
        if self.force:
            self.click_option_kwargs['default'] = lambda: default_val(self.config_name)

        if self.envvar is not None and self.envvar in os.environ:
            self.click_option_kwargs['default'] = os.environ[self.envvar]

        if not click_option_args:
            click_option_args = self.click_option_args

        return partial(
            click.option,
            *click_option_args,
            **self.click_option_kwargs
        )

    def retrieve_value(self):
        if self.envvar is not None and self.envvar in os.environ:
            return os.environ[self.envvar]
        else:
            return default_val(self.config_name)


def get_namespace():
    ns = pyk8s.cl.config.namespace
    return ns if ns != "default" else None

namespace = Option(
    '-n',
    '--namespace',
    config_name = key_namespace,
    default = lambda: get_namespace(),
    help = help_text(key_namespace),
    prompt_message = phrases.namespace,
    default_before_user_input = True
)

filepath = Option(
    '-f',
    '--filepath',
    config_name =key_install_filepath,
    help = help_text(key_install_filepath),
    type = click.Path(file_okay=True, readable=True, exists=True)
)

version = Option(
    '--version',
    config_name = key_version,
    required = True,
    help = help_text(key_version),
)

operator_version = Option(
    '--operator-version',
    config_name = key_operator_version,
    help = help_text(key_operator_version),
    type = click.STRING
)

output_file = Option(
    '--output-file',
    config_name = key_install_outputFile,
    help = help_text(key_install_outputFile),
    default = lambda: default_val(key_install_outputFile)
)

hostname = Option(
    '--hostname',
    '--ingress-host',
    config_name = key_hostname,
    help = help_text(key_hostname),
    prompt_message = phrases.hostname_entry
)

license_secret = Option(
    '--license-secret',
    config_name = key_license_secret,
    help = help_text(key_license_secret)
)

license_as_env_var = Option(
    '--license-as-env-var',
    config_name = key_license_envVar,
    help = help_text(key_license_envVar),
    type = bool
)

license_filepath = Option(
    '--license-filepath',
    config_name = key_license_filepath,
    help = help_text(key_license_filepath),
    prompt_message = phrases.license_entry
)

chart_repo_name = Option(
    '--chart-repo-name',
    config_name = key_chart_repo_name,
    help = help_text(key_chart_repo_name),
    prompt_message = phrases.chart_repo,
)

chart_repo_url = Option (
    '--chart-repo-url',
    config_name = key_chart_repo_url,
    prompt_message = phrases.chart_repo_url,
    help = help_text(key_chart_repo_url),
    hidden=True
)

chart_repo_username = Option (
    '--chart-repo-username',
    config_name = key_chart_repo_username,
    prompt_message = phrases.chart_user,
    help = help_text(key_chart_repo_username),
    hidden=True
)

chart_repo_password = Option (
    config_name = key_chart_repo_password,
    prompt_message = phrases.chart_password,
    help = help_text(key_chart_repo_password),
    password=True
)

client_cert_secret = Option (
    '--client-cert-secret',
    config_name = key_client_cert_secret,
    help=help_text(key_client_cert_secret)
)

image_repo = Option (
    '--image-repo',
    config_name = key_image_repository,
    prompt_message = phrases.image_repo,
    help=help_text(key_image_repository)
)

image_repo_user = Option (
    '--image-repo-user',
    config_name = key_image_repository_user,
    prompt_message = phrases.image_user,
    default=lambda: default_val(key_image_repository_user),
    help=help_text(key_image_repository_user)
)

image_repo_password = Option (
    config_name = key_image_repository_password,
    prompt_message = phrases.image_password,
    default=lambda: default_val(key_image_repository_password),
    help=help_text(key_image_repository_password),
    password=True
)

image_pull_secret = Option (
    '--image-pull-secret',
    config_name = key_image_pullSecret,
    default=None,
    help=help_text(key_image_pullSecret)
)

gui_client_secret = Option (
    '--gui-client-secret',
    config_name = key_gui_client_secret,
    fallback = lambda: generate_password(),
    help = help_text(key_gui_client_secret),
    password = True
)

operator_client_secret = Option (
    '--operator-client-secret',
    config_name = key_operator_client_secret,
    fallback = lambda: generate_password(),
    help = help_text(key_operator_client_secret),
    password = True
)

keycloak_secret = Option (
    '--keycloak-secret',
    config_name = key_keycloak_secret,
    default=None,
    help=help_text(key_keycloak_secret)
)

keycloak_admin_password = Option (
    config_name = key_keycloak_admin_password,
    prompt_message = phrases.keycloak_admin,
    default=lambda: default_val(key_keycloak_admin_password),
    help=help_text(key_keycloak_admin_password),
    password=True
)

keycloak_management_password = Option (
    config_name = key_keycloak_management_password,
    prompt_message = phrases.keycloak_manage,
    default=lambda: default_val(key_keycloak_management_password),
    help=help_text(key_keycloak_management_password),
    password=True
)

postgresql_postgres_password = Option (
    config_name = key_postgresql_postgres_password,
    prompt_message = phrases.postgresql_postgres,
    default=lambda: default_val(key_postgresql_postgres_password),
    help=help_text(key_postgresql_postgres_password),
    password=True
)

postgresql_user_password = Option (
    config_name = key_postgresql_user_password,
    prompt_message = phrases.postgresql_user,
    default=lambda: default_val(key_postgresql_user_password),
    help=help_text(key_postgresql_user_password),
    password=True
)

keycloak_postgresql_secret = Option (
    '--keycloak-postgresql-secret',
    config_name = key_keycloak_postgresqlSecret,
    default=None,
    help=help_text(key_keycloak_postgresqlSecret)
)

keycloak_auth_url = Option (
    '--keycloak-auth-url',
    config_name = key_keycloak_authURL,
    help=help_text(key_keycloak_authURL)
)

ingress_cert_secret = Option (
    '--ingress-cert-secret',
    config_name = key_ingress_cert_secret,
    help=help_text(key_ingress_cert_secret)
)

ingress_cert = Option (
    '--ingress-cert',
    config_name = key_ingress_cert,
    prompt_message = phrases.ingress_tls_cert,
    help=help_text(key_ingress_cert)
)

ingress_key = Option (
    '--ingress-key',
    config_name = key_ingress_key,
    prompt_message = phrases.ingress_tls_key,
    help=help_text(key_ingress_key)
)

ingress_certmanager_disabled = Option (
    '--ingress-certmanager-disabled',
    config_name = key_ingress_certmanager_disabled,
    help = help_text(key_ingress_certmanager_disabled),
    is_flag = True
)

assembly_backup_filepath = Option (
    '--assembly-backup-filepath',
    config_name = key_assembly_backup_file,
    help = help_text(key_assembly_backup_file),
    )

assembly_name = Option (
    '--name',
    help='Name of the assembly',
    required=True
)

assembly_wait = Option (
    '--wait',
    '--wait-for-ready',
    help='Wait for all pods',
    is_flag=True
)

assembly_filepath = Option (
    '-f',
    '--filepath',
    config_name = 'assembly.filepath',
    help='Path to the assembly file',
    prompt_message = 'Please enter a path to the assembly file'
)

client_id = Option (
    '--client-id',
    config_name = key_client_id,
    help = help_text(key_client_id),
    default = lambda: default_val(key_client_id),
    prompt_message = 'Please enter a client id to connect with',
    hidden=True
)


client_secret = Option (
    '--client-secret',
    config_name = key_client_secret,
    help = help_text(key_client_secret),
    default = lambda: default_val(key_client_secret),
    prompt_message = 'Please enter a client secret to connect with',
    password = True,
    hidden=True
)

serviceaccount_id = Option (
    '--serviceaccount-id',
    config_name = key_serviceaccount_id,
    help = help_text(key_serviceaccount_id),
    envvar='KXI_SERVICEACCOUNT_ID',
    default = lambda: default_val(key_serviceaccount_id),
    prompt_message = 'Please enter a service account id to connect with',
)

serviceaccount_secret = Option (
    '--serviceaccount-secret',
    config_name = key_serviceaccount_secret,
    help = help_text(key_serviceaccount_secret),
    envvar='KXI_SERVICEACCOUNT_SECRET',
    default=lambda: default_val(key_serviceaccount_secret),
    prompt_message = 'Please enter a service account secret to connect with (input hidden)',
    password = True
)

realm = Option (
    '--realm',
    config_name = key_keycloak_realm,
    help = help_text(key_keycloak_realm),
    default = lambda: default_val(key_keycloak_realm),
    prompt_message = 'Please enter a keycloak realm to connect with',
)

use_kubeconfig = Option (
    '--use-kubeconfig',
    help = 'Communicate directly with kubernetes plane',
    is_flag=True
)

import_users = Option (
    '--import-users',
    help = 'Enables/disables the import of users at deployment time',
    default = None,
    type = bool
)

admin_username = Option(
    '--admin-username',
    config_name = key_admin_username,
    help = help_text(key_admin_username),
    default = lambda: default_val(key_admin_username),
    prompt_message = 'Enter your admin username'
)

admin_password = Option(
    '--admin-password',
    config_name = 'admin.password',
    help = 'Administrator password',
    prompt_message = 'Enter your admin password'
)

timeout = Option(
    '--timeout',
    type = int,
    default = 2,
    help = 'Timeout in seconds for request'
)

temporary = Option(
    '--temporary/--not-temporary',
    default=True,
    help='Controls whether user must reset password on first login'
)

operator_revision = Option(
    '--operator-revision',
    default = None,
    help='Revision of operator to rollback to'

)

operator_history = Option (
    '--show-operator',
    default = None,
    help = 'Display the install history of the kxi-operator',
    is_flag=True
)

operator_chart = Option(
    '--operator-chart',
    default=f"{default_val(key_chart_repo_name)}/kxi-operator",
    help = 'Filename of kxi-operator chart',
)

serviceaccount = Option(
    '--serviceaccount',
    is_flag=True,
    help='Use service account login flow',
)

cache_file = Option(
    config_name = key_cache_file,
    default = lambda: default_val(key_cache_file),
    help='Location to cache the auth token'
)

auth_client = Option(
    config_name = key_auth_client,
    default = lambda: default_val(key_auth_client),
    help='Client to authenticate a user with'
)

def get_serviceaccount_id():
    ctx = click.get_current_context()

    service_id = ctx.params.get('serviceaccount_id')

    if service_id is None:
        service_id = serviceaccount_id.retrieve_value()

    if service_id is None:
        service_id = serviceaccount_id.prompt(ctx.params.get('client_id'))

    return service_id

def get_serviceaccount_secret():
    ctx = click.get_current_context()

    secret = ctx.params.get('serviceaccount_secret')

    if secret is None:
        secret = serviceaccount_secret.retrieve_value()

    if secret is None:
        secret = serviceaccount_secret.prompt(ctx.params.get('client_secret'))

    return secret

def get_hostname():
    ctx = click.get_current_context()
    host = ctx.params.get('hostname')
    kube_config = ctx.params.get('use_kubeconfig')

    if host is None:
        host = default_val('hostname')

    if host is None and kube_config is not None:
        return None

    if host is None:
        host = hostname.prompt(ctx.params.get('hostname'))

    return host