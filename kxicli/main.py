from kxicli import cli_group
from kxicli.commands import client, assembly, auth, entitlement, package, install, azure_idp, user, configure, backup, publish, query

__all__ = ["client", "assembly", "auth", "package", "install", "azure_idp", "user", "configure", "backup", "publish", "query", "cli", "entitlement"]

cli = cli_group.cli

cli.add_command(package.package)

if __name__ == '__main__':
    cli()  # pylint: disable=no-value-for-parameter
