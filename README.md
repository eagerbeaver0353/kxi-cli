# KX Insights CLI

The CLI provide features to perform operations such as

* Enrolling/removing clients
* Querying data
* Creating and deleting assemblies

etc

The CLI makes use of the Python Kubernetes client to allow it to run easily outside and inside of a Kubernetes cluster.

### Install

Clone the repository.

Run the following commands from inside the repository to create a virtual environment and install the CLI.

```shell-session
virtualenv charts/insights/test/cli/venv
. charts/insights/test/cli/venv/bin/activate
pip install --editable charts/insights/test/cli
```

`kxi` will now be available for you to execute.

```shell-session
(venv) $ kxi version
Version 0.1.0
```

To allow `kxi` to be called from outside of the `venv`, add the `venv` bin directory to your PATH.

```
(venv) $ deactivate # deactivate the venv if it's currently active
$ export PATH=$PATH:/path/to/venv/bin
$ kxi version
Version 0.1.0
```

### Configuration

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

