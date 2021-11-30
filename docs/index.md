# Overview

The CLI provides features to perform operations such as

* Installation setup
* Enrolling/removing clients
* Querying data
* Creating and deleting assemblies

etc

The CLI makes use of the Python Kubernetes client to allow it to run easily outside and inside of a Kubernetes cluster.

## Requirements

The CLI requires

* Python 3.6 or greater

## Install

To install from Nexus, create a virtual environment and execute `pip install` with the appropriate credentials.

```shell-session
virtualenv venv
source venv/bin/activate

pip_user=<redacted>
pip_password=<redacted>

pip install -v --extra-index-url https://$pip_user:$pip_password@nexus.dl.kx.com/repository/kxi-cli/simple kxicli
```

To install a specific version, use

```shell-session
cli_version=x.y.z # replace with the version you want to install
pip install -v --extra-index-url https://$pip_user:$pip_password@nexus.dl.kx.com/repository/kxi-cli/simple kxicli==$cli_version
```

Available versions can be viewed on [Nexus](https://nexus.dl.kx.com/#browse/browse:kxi-cli)

To install from source, clone the repository and run the following commands from inside the repository to create a virtual environment and run `pip install` inside the repository

```shell-session
virtualenv venv
source venv/bin/activate
pip install --editable .
```

Once installed, `kxi` will now be available for you to execute.

```shell-session
(venv) $ kxi --version
kxi, version 0.1.0 from /home/rtuser/git/kxi-cli/kxi (Python 3.8)
```

To allow `kxi` to be called from outside of the `venv`, add the `venv` bin directory to your PATH.

```shell-session
(venv) $ deactivate # deactivate the venv if it's currently active
$ export PATH=$PATH:/path/to/venv/bin
$ kxi --version
kxi, version 0.1.0 from /home/rtuser/git/kxi-cli/kxi (Python 3.8)
```

## Configuration

`kxi` is configured using a configuration file `~/.insights/cli-config`

Many commands require options that don't change often, such as the host that you're interacting with.

If you run `kxi configure` you will automatically be prompted for the necessary configuration and the configuration file will be created.

The configuration file allows these to be defaulted so you don't need to pass them everytime.

The currently supported settings are

|Setting|Description|
|-------|-----------|
|hostname|Hostname for the Insights installation to interact with|
|namespace|Namespace for Insights installation to interact with|
|client.id|Name of the default client|
|client.secret|Default client secret used to request access tokens|

These can be overridden by explicity passing the value if desired.

An example configuration file

```shell-session
$ cat ~/.insights/cli-config
[default]
hostname = https://my-host.kx.com
client.id = my-publisher
client.secret = my-secret
```

`kxi` also supports a global `--profile` option if you are frequently running commands against various different installs or for different clients.

A different profile can be added by calling `kxi configure --profile <name of new profile>`, then any command can use this profile when given the `--profile` flag.

