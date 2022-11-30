import click
import json
import kubernetes as k8s
import requests


def list(hostname, token):
    """List assemblies from kxi-controller"""
    headers = {
        'Authorization': f'Bearer {token}'
    }

    res = requests.get(f'{hostname}/kxicontroller/assembly/', headers=headers)
    res.raise_for_status()
    assemblies = json.loads(res.text)

    return assemblies


def status(hostname, token, name):
    """Get the status of an assembly via the kxi-controller"""
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    url = f'{hostname}/kxicontroller/assembly/cli/{name}'
    res = requests.get(url, headers=headers)

    if res.status_code == 404:
        raise click.ClickException(f'Assembly {name} not found')
    else:
        res.raise_for_status()

    res_text = res.text
    if len(res_text):
        res_text = json.loads(res_text)

    return res_text


def deploy(hostname, token, payload):
    """Create an assembly from kxi-controller"""
    headers = {
        'Authorization': f'Bearer {token}'
    }

    res = requests.post(f'{hostname}/kxicontroller/assembly/cli/deploy', headers=headers, json=payload)
    res.raise_for_status()

    return True


def teardown(hostname, token, name):
    """Teardown an assembly via the kxi-controller"""
    headers = {
        'Authorization': f'Bearer {token}'
    }
    
    url = f'{hostname}/kxicontroller/assembly/cli/{name}/teardown'
    res = requests.post(url, headers=headers)
    
    if res.status_code == 404:
        click.echo(f'Ignoring teardown, {name} not found')
        return False
    else:
        res.raise_for_status()

    return True
