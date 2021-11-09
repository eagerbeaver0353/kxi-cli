import click
import sys
import requests
from kxi import config
from kxi import log

# Generic help text dictionary for commands
help_text = {}
help_text['hostname'] = 'Hostname of Insights deployment.'

def get_default_val(option):
    """Get default value for an option from configuration"""
    return config.config.get(config.config.default_section, option, fallback='')

def get_access_token(hostname, client_id, client_secret):
    """Get Keycloak client access token"""
    log.debug('Requesting access token')
    url = hostname + '/auth/realms/insights/protocol/openid-connect/token'
    headers = {
        'Content-Type' : 'application/x-www-form-urlencoded'
    }
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }

    r = requests.post(url, headers=headers, data=payload)
    if r:
        return r.json()['access_token']

    log.error('Failed to request access token')
    click.echo(r.text)
    sys.exit(1)

def get_admin_token(hostname):
    """Get Keycloak Admin API token from hostname"""
    log.debug('Requesting admin access token')
    url = hostname + '/auth/realms/master/protocol/openid-connect/token'
    headers = {
        'Content-Type' : 'application/x-www-form-urlencoded'
    }

    #TODO: Make these configurable
    payload = {
        'grant_type': 'password',
        'username': 'user',
        'password': 'admin',
        'client_id': 'admin-cli'
    }
    r = requests.post(url, headers=headers, data=payload)
    if r:
        return r.json()['access_token']

    log.error('Failed to request admin access token')
    click.echo(r.text)
    sys.exit(1)
