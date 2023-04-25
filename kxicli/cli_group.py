import os
import sys
import click
import importlib
import pkg_resources

from click_aliases import ClickAliasedGroup

from kxicli import config
from kxicli import log

PYTHON_VERSION = f'{sys.version_info.major}.{sys.version_info.minor}'
PKG_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_MSG = f'%(prog)s, version %(version)s from {PKG_DIR} (Python {PYTHON_VERSION})'


@click.group(cls=ClickAliasedGroup)
@click.version_option(message=VERSION_MSG)
@click.option('--debug', is_flag=True, default=False, help='Enable debug logging.')
@click.option('--profile', default='default', help='Name of configuration profile to use.')
@click.pass_context
def cli(ctx, debug, profile):
    """kdb Insights Enterprise CLI"""
    ctx.obj = {}
    if debug:
        ctx.obj["debug"] = True
        log.GLOBAL_DEBUG_LOG = True
        log.debug(f'Version {importlib.metadata.version("kxicli")}')
        log.debug('Enabled global debug logging')

    config.load_config(profile)
    if profile not in config.config and ctx.invoked_subcommand != 'configure':
        config.set_config(profile)
    
    ctx.obj["kxi_cli_profile"] = profile
