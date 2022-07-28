import datetime
import json
import sys

import click
import requests
from tabulate import tabulate

from kxicli import common
from kxicli import log


@click.command()
@click.option('--hostname', default=lambda: common.get_default_val('hostname'), help=common.get_help_text('hostname'))
@click.option('--client-id', default=lambda: common.get_default_val('client.id'), help='Client ID to query with')
@click.option('--client-secret', default=lambda: common.get_default_val('client.secret'),
              help='Client secret to request access token')
@click.option('--table', required=True, help='Name of the table to query')
@click.option('--counts', is_flag=True, help='Only return the column count and row count of the returned data')
@click.option('--realm', default=lambda: common.get_default_val('realm'), help=common.get_help_text('realm'))
def query(hostname, client_id, client_secret, table, counts, realm):
    """Query a table for today's data"""
    token = common.get_access_token(hostname, client_id, client_secret, realm)
    url = f'{hostname}/servicegateway/kxi/getData'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'Accepted': 'application/json'
    }

    today = datetime.datetime.today().strftime('%Y.%m.%d')
    payload = {
        'table': table,
        'startTS': f'{today}D00:00:00.000000000',
        'endTS': f'{today}D23:59:59.999999999',
        'region': 'Canada'
    }

    log.debug(f'Query payload={json.dumps(payload, indent=2)}')
    r = requests.post(url, headers=headers, json=payload)
    if r and 'application/json' in r.headers.get('Content-Type'):
        payload = r.json()[1]

        if [] == payload:
            click.echo('Empty payload')
            sys.exit(0)
        elif counts:
            click.echo(f"{len(payload['x'])} column(s), {len(payload['y'][0])} row(s)")
        else:
            click.echo(tabulate(zip(*payload['y']), headers=payload['x']))
            sys.exit(0)
    else:
        log.error(r.text)
        sys.exit(1)
