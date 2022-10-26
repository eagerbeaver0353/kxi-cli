import click
import sys

import kubernetes as k8s

from kxicli import common, log


def create_namespace(name):
    common.load_kube_config()
    api = k8s.client.CoreV1Api()
    ns = k8s.client.V1Namespace()
    ns.metadata = k8s.client.V1ObjectMeta(name=name)
    try:
        api.create_namespace(ns)
    except k8s.client.rest.ApiException as exception:
        # 409 is a conflict, this occurs if the namespace already exists
        if not exception.status == 409:
            raise click.ClickException(f'Exception when trying to create namespace {exception}')
