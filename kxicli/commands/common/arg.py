from functools import partial

import click

from kxicli.common import get_default_val as default_val
from kxicli.common import get_help_text as help_text
from kxicli.common import key_chart_repo_name
from kxicli import options


def combine_decorators(*decorators):
    """
    This method takes decorators as arguments and combines them into a single decorator to reduce duplication
    """
    def combined(func):
        for decorator in reversed(decorators):
            func = decorator(func)
        return func
    return combined

force = partial(
    click.option, '--force', is_flag=True, help='Perform action without prompting for confirmation'
)

filepath = options.filepath.decorator()

operator_version = options.operator_version.decorator()

version = options.version.decorator()

release = partial(
    click.option, '--release', help=help_text('release.name'), default=lambda: default_val('release.name'),
    type=click.STRING
)

namespace = options.namespace.decorator()

assembly_backup_filepath = options.assembly_backup_filepath.decorator()

assembly_filepath = options.assembly_filepath.decorator()

assembly_name = options.assembly_name.decorator()

assembly_wait = options.assembly_wait.decorator()

output_file = options.output_file.decorator()

license_secret = options.license_secret.decorator()

license_as_env_var = options.license_as_env_var.decorator()

license_filepath = options.license_filepath.decorator()

hostname = options.hostname.decorator()

chart_repo_name = options.chart_repo_name.decorator()

chart_repo_url = options.chart_repo_url.decorator()

chart_repo_username = options.chart_repo_username.decorator()

chart_repo_password = options.chart_repo_password.decorator()

client_cert_secret = options.client_cert_secret.decorator()

image_repo = options.image_repo.decorator()

image_repo_user= options.image_repo_user.decorator()

image_pull_secret = options.image_pull_secret.decorator()

gui_client_secret = options.gui_client_secret.decorator()

operator_client_secret = options.operator_client_secret.decorator()

keycloak_secret = options.keycloak_secret.decorator()

keycloak_postgresql_secret = options.keycloak_postgresql_secret.decorator()

keycloak_auth_url = options.keycloak_auth_url.decorator()

ingress_cert_secret = options.ingress_cert_secret.decorator()

ingress_cert = options.ingress_cert.decorator()

ingress_key = options.ingress_key.decorator()

ingress_certmanager_disabled = options.ingress_certmanager_disabled.decorator()

client_id = options.client_id.decorator()

client_secret = options.client_secret.decorator()

serviceaccount_id = options.serviceaccount_id.decorator()

serviceaccount_secret = options.serviceaccount_secret.decorator()

realm = options.realm.decorator()

use_kubeconfig = options.use_kubeconfig.decorator()

import_users = options.import_users.decorator()

admin_username = options.admin_username.decorator()

admin_password = options.admin_password.decorator()

timeout = options.timeout.decorator()

temporary = options.temporary.decorator()

operator_revision = options.operator_revision.decorator()

operator_history = options.operator_history.decorator()

operator_chart = options.operator_chart.decorator()

serviceaccount = options.serviceaccount.decorator()

force_code = options.force_code.decorator()

management_version = options.management_version.decorator()

chart = partial(
    click.argument, 'chart', default=f"{default_val(key_chart_repo_name)}/insights"
)

# Group of decorators for 'kxi install setup'
install_setup_group = combine_decorators(
    namespace(),
    chart_repo_name(hidden=True),
    chart_repo_url(),
    chart_repo_username(),
    license_secret(),
    license_as_env_var(),
    license_filepath(),
    client_cert_secret(),
    image_repo(),
    image_repo_user(),
    image_pull_secret(),
    gui_client_secret(),
    operator_client_secret(),
    keycloak_secret(),
    keycloak_postgresql_secret(),
    keycloak_auth_url(),
    hostname(),
    ingress_cert_secret(),
    ingress_cert(),
    ingress_key()
)
