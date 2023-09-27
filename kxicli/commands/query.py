import click
import sys

from kxi.query import Query
from kxi import DeploymentType
from kxicli import common, options
from kxicli.commands.common import arg
from kxicli.cli_group import cli
from kxicli.resources.auth import TokenType
from kxi.rest import ApiClient
from kxicli.resources import auth as auth_lib
from kxi.auth import CredentialStore

@cli.command(usage=[DeploymentType.MICROSERVICES, DeploymentType.ENTERPRISE])
@arg.hostname()
@click.option('--usage', default=lambda: common.get_default_val('usage'),
              type=click.Choice(DeploymentType.values(), case_sensitive=False),
              help="kdb Insights deployment type: enterprise/microservices")
@arg.client_id()
@arg.client_secret()
@click.option('--sql', required=True, help="""
              The SQL query to be executed
""")
@click.option('--output-format',
              type=click.Choice(['tabular', 'csv', 'json', 'json_records'], case_sensitive=False),
              required=False,
              help="""
              tabular: print query results in tabular format (default)
              csv: print query results as csv
              json: print query results as columnar json
              json_records: print query results as a json object per row
""")
@click.option('--output-file', required=False, type=str, help='Optionally write results to an output_file instead of console')
@arg.realm()
def query(hostname, usage, client_id, client_secret, sql, output_format, output_file, realm):
    """Execute a SQL query and print results to console/file"""
    hostname = options.hostname.prompt(hostname, silent=True)
    conn = get_query_object(hostname, realm, usage.upper())

    df = conn.sql(sql).pd()
    
    target = sys.stdout
    if output_file:
        target = output_file
    
    if output_format == "csv":
        df.to_csv(target, index=False)
    elif output_format == "json":
        df.to_json(target)
    elif output_format == "json_records":
        df.to_json(target, orient="records", lines=True)
    else:
        df.to_string(target, index=False)

def get_query_object(hostname, realm, usage):

    store = CredentialStore(name = options.get_profile(), file_path= common.token_cache_file, 
                            file_format= common.token_cache_format)

    grant_type = store.get('grant_type', default=TokenType.SERVICEACCOUNT)
    client_id = options.get_serviceaccount_id()
    
    if grant_type == TokenType.USER:
        client_id = store.get('client_id')
        
    return Query(hostname, usage=usage, realm=realm, 
                    client_id=client_id, grant_type=grant_type,
                    client_secret = options.get_serviceaccount_secret(), cache=store)