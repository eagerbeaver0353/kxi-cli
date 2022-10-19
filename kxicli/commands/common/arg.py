from functools import partial

import click

from kxicli.common import get_default_val as default_val
from kxicli.common import get_help_text as help_text
from kxicli import options


arg_force = partial(
    click.option, '--force', is_flag=True, help='Perform action without prompting for confirmation'
)

arg_filepath = options.filepath.decorator()

arg_operator_version = options.operator_version.decorator()

arg_version = options.version.decorator()

arg_release = partial(
    click.option, '--release', help=help_text('release.name'), default=lambda: default_val('release.name'),
    type=click.STRING
)

arg_namespace = options.namespace.decorator()

arg_assembly_backup_filepath = partial(
    click.option, '--assembly-backup-filepath', default=lambda: default_val('assembly.backup.file'),
    help=help_text('assembly.backup.file'),
    type=click.STRING
)

arg_output_file = options.output_file.decorator()

arg_license_secret = options.license_secret.decorator()

arg_license_as_env_var = options.license_as_env_var.decorator()

arg_license_filepath = options.license_filepath.decorator()

arg_hostname = options.hostname.decorator()

arg_chart_repo_name = options.chart_repo_name.decorator()

arg_chart_repo_url = options.chart_repo_url.decorator()

arg_chart_repo_username = options.chart_repo_username.decorator()

arg_chart_repo_password = options.chart_repo_password.decorator()

arg_client_cert_secret = options.client_cert_secret.decorator()

arg_image_repo = options.image_repo.decorator()

arg_image_repo_user= options.image_repo_user.decorator()

arg_image_pull_secret = options.image_pull_secret.decorator()

arg_gui_client_secret = options.gui_client_secret.decorator()

arg_operator_client_secret = options.operator_client_secret.decorator()

arg_keycloak_secret = options.keycloak_secret.decorator()

arg_keycloak_postgresql_secret = options.keycloak_postgresql_secret.decorator()

arg_keycloak_auth_url = options.keycloak_auth_url.decorator()

arg_ingress_cert_secret = options.ingress_cert_secret.decorator()

arg_ingress_cert = options.ingress_cert.decorator()

arg_ingress_key = options.ingress_key.decorator()

arg_install_config_secret = options.install_config_secret.decorator()
