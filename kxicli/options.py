import click
import sys
import kubernetes as k8s
import kxicli.common

from functools import partial
from kxicli import config
from kxicli import phrases
from kxicli.common import get_default_val as default_val
from kxicli.common import get_help_text as help_text
from kxicli.common import key_install_outputFile, key_chart_repo_name, key_install_config_secret, \
    key_image_repository, key_image_repository_user, key_image_repository_password, key_image_pullSecret, \
    key_ingress_cert_secret, key_ingress_self_managed, key_ingress_cert, key_ingress_key
from kxicli.common import enter_password

def _is_interactive_session():
    return sys.stdout.isatty() and '--force' not in sys.argv

def prompt_error_message(self):
    error_message = 'Could not find expected option.'
    if self.click_option_args:
        error_message = error_message + f' Please set command line argument {self.click_option_args[0]}'
        if self.config_name:
            error_message = error_message + f' or configuration value {self.config_name} in config file {config.config_file}'
    elif self.config_name:
        error_message = error_message + f' Please set configuration value {self.config_name} in config file {config.config_file}'

    return error_message

class Option():
    def __init__(self, *click_option_args , config_name=None, force=False, password=False, prompt_message='', **click_option_kwargs):
        self._click_option_args = click_option_args
        self._click_option_kwargs = click_option_kwargs
        self._config_name = config_name
        self._force = force
        self._password = password
        self._prompt_message = prompt_message

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
    def force(self):
        return self._force

    @property
    def password(self):
        return self._password

    @property
    def prompt_message(self):
        return self._prompt_message


    def prompt(self, cmd_line_value=None, **kwargs):
        prompt_message = None

        if kwargs.get('prompt_message'):
            prompt_message = kwargs.get('prompt_message')
        elif self.prompt_message:
            prompt_message = self.prompt_message

        # cmd line arg
        if cmd_line_value is not None:
            if self.click_option_kwargs.get('default') is None:
                click.echo(f'Using {self.config_name} {cmd_line_value} from command line option')
            return cmd_line_value
        # config file
        elif config.config.has_option(config.config.default_section, self.config_name):
            val = config.config.get(config.config.default_section, self.config_name)
            click.echo(f'Using {self.config_name} {val} from config file {config.config_file}')
            return val
        # check if there's a tty and not explicitly no prompt
        elif prompt_message and _is_interactive_session():
            if self.password:
                return enter_password(prompt_message)
            else:
                return click.prompt(prompt_message, default=default_val(self.config_name))
        # embedded default values
        elif self.config_name in kxicli.common.DEFAULT_VALUES:
            val = kxicli.common.DEFAULT_VALUES[self.config_name]
            click.echo(f'Using {self.config_name} {val} from embedded default values')
            return val
        else:
            raise click.ClickException(prompt_error_message(self))


    def decorator(self):
        if self.force:
            self.click_option_kwargs['default'] = default_val(self.config_name)
        
        return partial(
            click.option,
            *self.click_option_args,
            **self.click_option_kwargs
        )


def get_namespace():
    _, active_context = k8s.config.list_kube_config_contexts()
    if 'namespace' in active_context['context']:
        return active_context['context']['namespace']


namespace = Option(
    '--namespace',
    config_name = 'namespace',
    default = lambda: get_namespace(),
    help = help_text('namespace'),
    prompt_message = phrases.namespace
)

filepath = Option(
    '--filepath',
    config_name = 'install.filepath',
    help = help_text('install.filepath'),
    type = click.Path(file_okay=True, readable=True, exists=True)
)

version = Option(
    '--version', 
    required = True, 
    help = help_text('version'),
)

operator_version = Option(
    '--operator-version', 
    help = help_text('operator.version'),
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
    config_name = 'hostname',
    help = help_text('hostname'),
    prompt_message = phrases.hostname_entry
)

license_secret = Option(
    '--license-secret',
    config_name = 'license.secret',
    help = help_text('license.secret')
)

license_as_env_var = Option(
    '--license-as-env-var',
    config_name = 'license.as-env-var',
    help = help_text('license.envVar'),
    type = bool
)

license_filepath = Option(
    '--license-filepath',
    config_name = 'license.path',
    help = help_text('license.path'),
    prompt_message = phrases.license_entry
)

chart_repo_name = Option(
    '--chart-repo-name',
    config_name = key_chart_repo_name,
    help = help_text(key_chart_repo_name),
    prompt_message = phrases.chart_repo,
)

chart_repo_name_forced = Option(
    '--chart-repo-name',
    config_name = key_chart_repo_name,
    help = help_text(key_chart_repo_name),
    prompt_message = phrases.chart_repo,
    force=True
)

chart_repo_url = Option (
    '--chart-repo-url',
    config_name = 'chart.repo.url',
    prompt_message = phrases.chart_repo_url,
    help = help_text('chart.repo.url')
)

chart_repo_username = Option (
    '--chart-repo-username',
    config_name = 'chart.repo.username',
    prompt_message = phrases.chart_user,
    help = help_text('chart.repo.username')
)

chart_repo_password = Option (
    config_name = 'chart.repo.password',
    prompt_message = phrases.chart_password,
    help = help_text('chart.repo.password'),
    password=True
)

client_cert_secret = Option (
    '--client-cert-secret',
    help=help_text('client.cert.secret')
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
    default=None,
    help=help_text(key_image_pullSecret)
)

gui_client_secret = Option (
    '--gui-client-secret',
    default=lambda: default_val('guiClientSecret'),
    help=help_text('guiClientSecret')
)

operator_client_secret = Option (
    '--operator-client-secret',
    default=lambda: default_val('operatorClientSecret'),
    help=help_text('operatorClientSecret')
)

keycloak_secret = Option (
    '--keycloak-secret',
    default=None,
    help=help_text('keycloak.secret')
)

keycloak_postgresql_secret = Option (
    '--keycloak-postgresql-secret',
    default=None,
    help=help_text('keycloak.postgresqlSecret')
)

keycloak_auth_url = Option (
    '--keycloak-auth-url',
    help=help_text('keycloak.authURL')
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

install_config_secret = Option (
    '--install-config-secret',
    config_name = key_install_config_secret,
    help=help_text(key_install_config_secret)
)

install_config_secret_default = Option (
    '--install-config-secret',
    default = lambda: default_val(key_install_config_secret),
    help = help_text(key_install_config_secret)
)
