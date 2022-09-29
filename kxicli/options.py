import click
import sys
import kxicli.common

from functools import partial
from kxicli import phrases
from kxicli.common import get_default_val as default_val
from kxicli.common import get_help_text as help_text
from kxicli.common import key_install_outputFile, key_chart_repo_name, key_install_config_secret

def _is_interactive_session():
    return sys.stdout.isatty() and '--force' not in sys.argv

class Option():
    def __init__(self, *click_option_args , config_name=None, force=False, prompt_message='', **click_option_kwargs):
        self._click_option_args = click_option_args
        self._click_option_kwargs = click_option_kwargs
        self._config_name = config_name
        self._force = force
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
    def prompt_message(self):
        return self._prompt_message


    def prompt(self, cmd_line_value=None):
        # read value in hierarchy of cmd line arg, config value, default value, user prompt response
        if cmd_line_value:
            return cmd_line_value
        # check if there's a tty and not explicitly no prompt
        elif self.prompt_message and _is_interactive_session():
            return click.prompt(self.prompt_message, default=default_val(self.config_name))
        elif default_val(self.config_name):
            return default_val(self.config_name)
        else:
            raise click.ClickException(f'Must either set command line arg {self.click_option_args[0]} or configuration value {self.config_name}')

    def decorator(self):
        if self.force:
            self.click_option_kwargs['default'] = default_val(self.config_name)
        
        return partial(
            click.option,
            *self.click_option_args,
            **self.click_option_kwargs
        )

namespace = Option(
    '--namespace',
    config_name = 'namespace',
    help = help_text('namespace'),
    type = click.STRING
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

client_cert_secret = Option (
    '--client-cert-secret',
    help=help_text('client.cert.secret')
)

image_repo = Option ( 
    '--image-repo',
    default=lambda: default_val('image.repository'),
    help=help_text('image.repository')
)

image_pull_secret = Option (
    '--image-pull-secret',
    default=None,
    help=help_text('image.pullSecret')
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
    default=None,
    help=help_text('ingress.cert.secret')
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
