import json
import os
import pytest
import requests_mock

from kxicli import common
from kxicli.commands import assembly_kxicontroller
from utils import return_none

common.config.config_file = os.path.dirname(__file__) + '/files/test-cli-config'
common.config.load_config("default")

TEST_HOSTNAME = 'https://test.kx.com'
TEST_CLIENT_ID = 'test'
TEST_CLIENT_SECRET = 'secret'

def build_assembly_object_kxic(name, running= True, ready=True):
    """
    Create an assembly object as returned from the kxicontroller API
    Optionally add the status & last-applied-configuration annotation
    """
    return {
        "apiVersion": "insights.kx.com/v1",
        "name": name,
        "hasResources": True,
        "running": running,
        "ready": ready,
        "syncStatus": False,
        "labels": {
            "assemblyname": name
        },
        "queryEnvironment": {
            "enabled": True,
            "size": 1
        },
        "schema": {
            "id": "38cb0a24-dfd5-e395-8007-6f3ebe921460",
            "name": "dfxSchema"
        },
        "database": {
            "id": "3d42da2c-8ea4-5e4c-9152-db4b82a0e777",
            "name": "dfx-database"
        },
        "streams": [
            {
            "id": "79c092d0-c158-41b2-2db7-502270a45e77",
            "name": "dfx-north"
            },
            {
            "id": "fb5f470c-a5d6-1f74-ec4b-a417b47cc533",
            "name": "dfx-south"
            }
        ],
        "pipelines": [
            {
            "id": "898a109d-00e5-0981-0cb6-4a55a56a24e4",
            "name": "dfx-pipeline"
            }
        ],
        "k8sStatus": [
            {
            "status": "True",
            "type": "MountReady"
            },
            {
            "lastTransitionTime": "2022-11-28T12:02:15Z",
            "lastUpdateTime": "2022-11-28T12:02:15Z",
            "status": "True",
            "type": "StorageManagerReady"
            },
            {
            "lastTransitionTime": "2022-11-28T12:02:06Z",
            "lastUpdateTime": "2022-11-28T12:02:06Z",
            "status": "True",
            "type": "DataAccessReady"
            },
            {
            "lastTransitionTime": "2022-11-28T12:03:04Z",
            "lastUpdateTime": "2022-11-28T12:03:04Z",
            "status": "True",
            "type": "SequencerReady"
            },
            {
            "lastTransitionTime": "2022-11-28T12:02:28Z",
            "lastUpdateTime": "2022-11-28T12:02:28Z",
            "status": "True",
            "type": "PipelineReady"
            },
            {
            "lastTransitionTime": "2022-11-28T12:02:17Z",
            "lastUpdateTime": "2022-11-28T12:02:17Z",
            "status": "True",
            "type": "QueryEnvironmentReady"
            },
            {
            "lastTransitionTime": "2022-11-28T12:03:04Z",
            "lastUpdateTime": "2022-11-28T12:03:04Z",
            "status": "True",
            "type": "AssemblyReady"
            }
        ]
    }

            

def test_kxic_assembly_cli_list(mocker):
    asm_list = json.dumps([build_assembly_object_kxic(name='asm1'),build_assembly_object_kxic(name='asm2')])
    with requests_mock.Mocker() as m:
        m.get('https://test.kx.com/kxicontroller/assembly/', text=json.dumps(asm_list))
        assert assembly_kxicontroller.list(TEST_HOSTNAME, None) == asm_list
    