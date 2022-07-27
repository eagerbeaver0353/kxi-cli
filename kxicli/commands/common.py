from functools import partial

import click

from kxicli.common import get_default_val as default_val
from kxicli.common import get_help_text as help_text

arg_force = partial(
    click.option, '--force', is_flag=True, help='Perform installation without prompting for confirmation'
)

arg_filepath = partial(
    click.option, '--filepath', help='Values file to install with',
    type=click.Path(file_okay=True, readable=True, exists=True)
)

arg_operator_version = partial(
    click.option, '--operator-version', default=None, help='Version of the operator to install',
    type=click.STRING
)

arg_version = partial(
    click.option, '--version', required=True, help='Version to install',
    type=click.STRING
)

arg_release = partial(
    click.option, '--release', help=help_text('release.name'), default=lambda: default_val('release.name'),
    type=click.STRING
)

arg_namespace = partial(
    click.option, '--namespace', help=help_text('namespace'), default=lambda: default_val('namespace'),
    type=click.STRING
)

arg_assembly_backup_filepath = partial(
    click.option, '--assembly-backup-filepath', default=lambda: default_val('assembly.backup.file'),
    help=help_text('assembly.backup.file'),
    type=click.STRING
)
