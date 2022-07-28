# CLI Development

## Basic `Click`

`Click` is a package that enables you to easily create command line interfaces from standard Python functions.

It uses decorators to allow Python functions to be executed from the command line.

### Initial CLI

```python
# cli.py
import click

@click.command()
@click.option('--name', required=True, help='Name of user to logout')
def logout(name):
    click.echo(f'Goodbye {name}')

if __name__ == '__main__':
    logout()
```

`@click.command()` indicates that the following function is a Click command. `@click.option` specifies that you want to
be able to pass an option called `name` on the command line, this is passed by Click as a parameter to the function.

Note the use of `click.echo` in place of `print`, Click aims to be compatible between Python 2 and 3 and also adds
support for ANSI colours if available.

```shell-session
$ python cli.py
Usage: cli.py [OPTIONS]
Try 'cli.py --help' for help.

Error: Missing option '--name'.

$ python cli.py --name developer
Goodbye developer
```

### Allowing the CLI to be called directly

To call the CLI directly as a named command you can use `setuptools`.

Creating a `setup.py` file will allow us to install our CLI using `pip` and execute the CLI using a named command.

If you create the below `setup.py` in the same folder as `cli.py`

```python
# setup.py
from setuptools import setup
  
setup(
    name='devcli', # Name for the package
    version='0.1.0', # Version for the package
    py_modules=['devcli'], # Modules included in the package
    install_requires=[ 
        'Click', # Dependencies required for the package
    ],  
    entry_points={
        'console_scripts': [
            'dev = cli:logout',  # Generates the named command 'dev' which calls the function logout in the file cli.py
        ],  
    },  
)
```

you can install the package in editable mode with `pip`

```shell-session
$ ls .
cli.py setup.py
$ pip install --editable .
```

Now you can call `dev` and it will behave the same as if you called `python cli.py`

```shell-session
$ dev --name developer
Goodbye developer
```

Note, you no longer need the block

```python
if __name__ == '__main__':
    logout()
```

when running like this, calling the `logout` function is handled automatically by the `entrypoint` in the `setup.py`

### Prompting

`Click` provides the ability to prompt for user input. This can be used to ask the user for a name if one isn't provided
as an option

```python
# cli.py
import sys # Import sys to see the command line args
import click

@click.command()
@click.option('--name', help='Name of user to logout') # This is now optional because it no longer has required=True
def logout(name):
    # Check if --name exists and prompt for it if not
    if '--name' not in sys.argv:
        name = click.prompt('Enter a name')

    click.echo(f'Goodbye {name}')
```

Running the `dev` command you now see

```shell-session
dev
Enter a name: developer
Goodbye developer
```

### Confirmation prompts

`Click` has a special type of prompt for getting user confirmation. This is useful for destructive operations like
deleting files.

The example here shows how it can be used to confirm that you want to logout.

```python
# cli.py
import sys
import click

@click.command()
@click.option('--name', help='Name of user to logout')
def logout(name):
    # Check if --name exists and prompt for it if not
    if '--name' not in sys.argv:
        name = click.prompt('Enter a name')

    if click.confirm(f'Are you sure you want to logout {name}'):
        click.echo(f'Goodbye {name}')
```

```shell-session
$ dev --name developer
Are you sure you want to logout developer [y/N]: y
Goodbye developer
```

### Command groups

So far the CLI only performs one action. Multiple functions can be grouped together to make a more powerful CLI.

This is done using the `@click.group` decorator.

```python
import sys
import click

@click.group() 
def main(): # Placeholder function to attach multiple functions to
    pass

@main.command()  # Notice that this has changed from '@click.command()' to '@<group function>.command()`
@click.option('--name', help='Name of user to logout')
def logout(name):
    # Check if --name exists and prompt for it if not
    if '--name' not in sys.argv:
        name = click.prompt('Enter a name')

    if click.confirm(f'Are you sure you want to logout {name}'):
        click.echo(f'Goodbye {name}')

@main.command()
@click.option('--name', help='Name of user to login')
def login(name):
    # Check if --name exists and prompt for it if not
    if '--name' not in sys.argv:
        name = click.prompt('Enter a name')

    click.echo(f'Hello {name}')
```

You will now want your entrypoint to point to the `main` function instead of `logout` so `setup.py` needs to be updated.

```python
# setup.py
from setuptools import setup
  
setup(
    name='devcli',
    version='0.1.0',
    py_modules=['devcli'],
    install_requires=[ 
        'Click',
    ],  
    entry_points={
        'console_scripts': [
            'dev = cli:main',  # Now points to the 'main' function instead of 'logout'
        ],  
    },  
)
```

Anytime `setup.py` is changed you need to reinstall the package for the change to take effect.

```shell-session
pip install --editable .
```

Once this is done you now can call both `login` and `logout` from the `dev` command

```shell-session
$ dev
Usage: dev [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  login
  logout

$ dev login
Enter a name: developer
Hello developer

$ dev logout --name developer 
Are you sure you want to logout developer [y/N]: y
Goodbye developer
```

### System commands

System commands can be run from Python using the `subprocess` module.

For example if you need to use `helm` there is no official Helm Python client so you need to call out to the `helm` CLI.

The `run` function in the subprocess module makes it very easy to call these commands.

```python
# cli.py
import subprocess

# Omitted other commands

@main.command()
@click.option('--namespace', help='Namespace to list the releases from')
def releases(namespace):
    cmd = [ 'helm', 'list' ]
    if '--namespace' in sys.argv:
        cmd = cmd + [ '--namespace', namespace ]

    try:
        subprocess.run(cmd, check=True) # check=True raises an exception if the subprocess fails
    except subprocess.CalledProcessError as e:
      click.echo(e)
      sys.exit(e.returncode)
```

```shell-session
$ dev releases
NAME    	NAMESPACE	REVISION	UPDATED                                	STATUS  	CHART              	APP VERSION
insights	kyle     	1       	2022-02-16 09:57:21.862295848 -0800 PST	deployed	insights-1.0.0-rc.1	1.0.0-rc.1 
```

### Kubernetes interaction

Kubernetes has an official Python client that provides Python classes and methods for all of the exposed APIs.

The common pattern for using these is

1. Load the Kubernetes config file to get authorization tokens for the API
2. Create an instance of the API class that you want to use, essentially equivalent to the `apiVersion` in the yaml
   manifests
3. Try to run the call
4. Catch any exceptions

For example

```python
# cli.py
import kubernetes as k8s

# Omitted other commands

@main.command()
@click.option('--namespace', required=True, help='Namespace to list the pods from')
def pods(namespace):
    # 1. Load the config
    k8s.config.load_config()
    # 2. Create an instance of the Core V1 API
    v1 = k8s.client.CoreV1Api()
    # 3. Try to run the call
    try:
        click.echo('Listing pods with their IPs:')
        resp = v1.list_namespaced_pod(namespace=namespace)
        for item in resp.items:
            click.echo(f'{item.status.pod_ip}\t{item.spec.node_name}\t{item.metadata.name}')
    # 4. Catch any exceptions
    except k8s.client.rest.ApiException as e:
        click.echo(f'Exception when calling CoreV1Api->list_namespace_pod: {e}')
```

The Kubernetes package isn't in the standard library so this needs to be added to the `setup.py` to ensure it exists for
the install.

```
# setup.py
from setuptools import setup
  
setup(
    name='devcli',
    version='0.1.0',
    py_modules=['devcli'],
    install_requires=[ 
        'Click',
        'kubernetes' # Add a requirement on kubernetes
    ],  
    entry_points={
        'console_scripts': [
            'dev = cli:main',
        ],  
    },  
)
```

```shell-session
$ dev pods --namespace default | head
Listing pods with their IPs:
10.0.5.2	gke-gcp-red-default-node-pool-92a7-4d3235a1-9ggb	gcp-ssd-config-2n7gg
10.0.3.5	gke-gcp-red-default-node-pool-92a7-4d3235a1-qnht	gcp-ssd-config-6ngj9
10.0.0.5	gke-gcp-red-default-node-pool-92a7-4d3235a1-8ks3	gcp-ssd-config-pqtqs
10.0.4.4	gke-gcp-red-default-node-pool-92a7-4d3235a1-14jn	gcp-ssd-config-r8fvc
10.0.6.5	gke-gcp-red-default-node-pool-92a7-4d3235a1-f8lm	gcp-ssd-config-w4njd
10.0.1.4	gke-gcp-red-default-node-pool-92a7-4d3235a1-4fbf	gcp-ssd-config-zvrjl
10.0.0.152	gke-gcp-red-default-node-pool-92a7-4d3235a1-8ks3	pvc-cleanup-cronjob-27415080-c7sn8
10.0.0.172	gke-gcp-red-default-node-pool-92a7-4d3235a1-8ks3	pvc-cleanup-cronjob-27416520-bvwhz
10.0.0.251	gke-gcp-red-default-node-pool-92a7-4d3235a1-8ks3	pvc-cleanup-cronjob-27417960-wlg8b
```

