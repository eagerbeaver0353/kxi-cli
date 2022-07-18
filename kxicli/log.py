import click

GLOBAL_DEBUG_LOG = False

def debug(msg):
    if GLOBAL_DEBUG_LOG:
        click.echo(f"{click.style('debug', fg='blue')}={msg}")

def error(msg):
    click.echo(f"{click.style('error', fg='red', bold=True)}={msg}")

def warn(msg):
    click.echo(f"{click.style('warn', fg='yellow')}={msg}")
