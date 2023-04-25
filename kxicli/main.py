from kxicli import cli_group
from kxicli.commands import client, assembly, auth, install, package, azure_idp, user, configure, backup

cli = cli_group.cli

cli.add_command(client.client)
cli.add_command(assembly.assembly)
cli.add_command(auth.auth)
cli.add_command(azure_idp.idp)
cli.add_command(azure_idp.mapper)
cli.add_command(install.install)
cli.add_command(configure.configure)
cli.add_command(package.package)
cli.add_command(user.user)
cli.add_command(backup.backup)

if __name__ == '__main__':
    cli()  # pylint: disable=no-value-for-parameter
