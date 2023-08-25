import os
import sys
import click
import importlib

from click_aliases import ClickAliasedGroup
from kxi import DeploymentType
from kxicli import config, common
from kxicli import log
from kxicli.resources.auth import AuthCache

PYTHON_VERSION = f'{sys.version_info.major}.{sys.version_info.minor}'
PKG_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_MSG = f'%(prog)s, version %(version)s from {PKG_DIR} (Python {PYTHON_VERSION})'


class ProfileAwareGroup(ClickAliasedGroup):

    def __init__(self, *args, **kwargs):
        super(ProfileAwareGroup, self).__init__(*args, **kwargs)
        self._cli_usage = None
        self._profile = None

    def get_cli_usage(self, ctx):
        profile = None
        if "profile" in ctx.params:
            profile = ctx.params["profile"]
        else:
            parser = self.make_parser(ctx)
            parser.allow_interspersed_args = True
            parser.ignore_unknown_options = True
            opts, args, param_order = parser.parse_args(sys.argv[1:])
            if "profile" in opts:
                profile = opts["profile"]
            
        profile_usage = DeploymentType.ENTERPRISE
        
        if profile:
            config.load_config(profile)
            profile_usage = common.get_default_val("usage")

        self._cli_usage = profile_usage or DeploymentType.ENTERPRISE
        return self._cli_usage

    def command(self, *args, usage=[DeploymentType.ENTERPRISE], **kwargs):        
        cmd = super(ProfileAwareGroup, self).command(*args, context_settings={"obj": {"usage": usage}}, **kwargs)
        return cmd

    def group(self, *args, usage=[DeploymentType.ENTERPRISE], **kwargs):
        return super(ProfileAwareGroup, self).group(*args, context_settings={"obj": {"usage": usage}}, **kwargs)

    def get_command(self, ctx, cmd_name):
        cmd = super().get_command(ctx, cmd_name)
        if cmd and self.get_cli_usage(ctx) in cmd.context_settings.get("obj", {}).get("usage", DeploymentType.ENTERPRISE):
            return cmd
        else:
            return None
        
    def resolve_command(self, ctx, args):
        return super().resolve_command(ctx, args)
  

@click.group(cls=ProfileAwareGroup)
@click.version_option(message=VERSION_MSG)
@click.option('--debug', is_flag=True, default=False, help='Enable debug logging.')
@click.option('--profile', default='default', help='Name of configuration profile to use.')
@click.pass_context
def cli(ctx, debug, profile):
    """kdb Insights Enterprise CLI"""
    ctx.obj = ctx.obj or {}
    if debug:
        ctx.obj["debug"] = True
        log.GLOBAL_DEBUG_LOG = True
        log.debug(f'Version {importlib.metadata.version("kxicli")}')
        log.debug('Enabled global debug logging')

    config.load_config(profile)
    if profile not in config.config and ctx.invoked_subcommand != 'configure':
        config.set_config(profile)

    ctx.obj["kxi_cli_profile"] = profile
    ctx.obj["kxi_auth_class"] = AuthCache
