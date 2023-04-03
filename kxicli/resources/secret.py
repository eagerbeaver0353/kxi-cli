import click
import kubernetes as k8s

from kxicli import common
from kxicli import log
from kxicli import phrases

class Secret():
    def __init__(self, namespace, name, type = None, required_keys = (), data = None, string_data = None):
        self.namespace = namespace
        self.name = name
        self.type = type
        self.required_keys = required_keys
        self.data = data
        self.string_data = string_data


    def create(self):
        """Creates the secret in Kubernetes"""
        secret = self.get_body()
        common.load_kube_config()
        try:
            created_secret = k8s.client.CoreV1Api().create_namespaced_secret(self.namespace, body=secret)
        except k8s.client.rest.ApiException as exception:
            log.error(f'Exception when trying to create secret {exception}')
            return exception

        click.echo(phrases.secret_created.format(name=self.name))
        return created_secret

    def read(self):
        """Reads a Kubernetes secret"""
        common.load_kube_config()
        try:
            secret = k8s.client.CoreV1Api().read_namespaced_secret(namespace=self.namespace, name=self.name)
        except Exception as e:
            log.debug(f'Exception when calling read_namespaced_secret  {e}')
            return None

        return secret


    def patch(self):
        """Updates the Kubernetes secret"""
        log.debug(f'Updating secret {self.name} in namespace {self.namespace}')

        secret = self.get_body()
        common.load_kube_config()
        try:
            patched_secret = k8s.client.CoreV1Api().patch_namespaced_secret(self.name, self.namespace, body=secret)
        except k8s.client.rest.ApiException as exception:
            log.error(f'Exception when trying to update secret {exception}')
            return exception

        click.echo(phrases.secret_updated.format(name=self.name))
        return patched_secret


    def exists(self):
        """Checks if the secret exists in Kubernetes"""
        return self.read() is not None


    def get_body(self):
        """Forms a Kubernetes secret body from properties"""
        secret = k8s.client.V1Secret()
        secret.metadata = k8s.client.V1ObjectMeta(namespace=self.namespace, name=self.name)
        secret.type = self.type
        secret.data = self.data
        secret.string_data = self.string_data
        return secret


    def validate(self):
        """Validates a secret exists and has the correct format"""
        secret = self.read()
        exists = True
        is_valid = True
        missing_data_keys = []

        # existence check
        if secret is None:
            log.debug(f'Secret {self.name} does not exist in the namespace {self.namespace}')
            exists = False

        # run validation checks if the secret exists and has validation logic
        if exists:
            # type check
            if self.type is not None and secret.type != self.type:
                log.error(f'Secret {self.name} is of type {secret.type} when it should {self.type}')
                is_valid = False


            # all required keys check
            missing_data_keys = self.get_missing_keys(secret.data)
            if missing_data_keys:
                log.error(f'Secret {self.name} is missing required data keys {missing_data_keys}')
                is_valid = False

        return (exists, is_valid, missing_data_keys)


    def get_missing_keys(self, data):
        """Returns required keys that are missing from the secret data"""
        missing_keys = []
        # if the dictionary doesn't exist then all of the keys are missing
        if data is None:
            missing_keys = list(self.required_keys)
        else:
            for k in self.required_keys:
                if k not in data:
                    missing_keys.append(k)
        return missing_keys
