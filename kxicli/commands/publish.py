#cSpell:words dbpublisher QIPC timespan

import json
import click
from kxi import DeploymentType
from kxicli import common, options
from kxicli.cli_group import cli
from kxicli.commands.common import arg
from kxi.publish.dbpublisher import DBPublisher
from urllib.parse import urlparse

 
@cli.command(usage=[DeploymentType.MICROSERVICES])
@arg.hostname()
@click.option('--port', default=lambda: common.get_default_val('tp_port'), type=int, help='the port at the host (TP/QIPC)')
@click.option('--data', required=True, help="""              
The following use cases are supported:
- a file path on the local filesystem (eg. '/home/user/data.csv')
- an HTTP/S3/GS URL
    - http://localhost:8080/data.csv
    - s3://bucket_name/data.csv
    - gs://bucket_name/data.csv
- a directory ('/home/user/data') - in this case,
    all files in the directory get published (non-recursive)
""")
@click.option('--table', required=True,
              help='the name of a table in the database to insert data into')
@click.option(
        '--file-format', default=None,
        type=click.Choice(['csv', 'json', 'parquet', 'json_records'], case_sensitive=False),
            help="""If file_format is not provided,
              it will be set based on the file extension.""")
@click.option('--type-map', default=None, help=
            """JSON object of column names
            -> target data types to override default Pandas type casting.
            Target data type can be timespan, timestamp, numeric.
            Example: type_map={"time": "TIMEDELTA", "realTime": "DATETIME"}
""")
def publish(hostname, port, data, table, file_format, type_map):
    """Publish files through the TP port with QIPC"""
    
    hostname = options.hostname.prompt(hostname, silent=True)
    host = urlparse(hostname).hostname or hostname
    
    if type_map and isinstance(type_map, str):
        type_map = json.loads(type_map)
    with DBPublisher(host=host, port=port) as pub:
        click.echo(f"Publishing {data}")
        pub.publish(data, table, file_format, type_map)
        click.echo(f"{data} published")

