from __future__ import annotations
import os
from pathlib import Path
import json
from typing import Optional
from unittest.mock import MagicMock
import click
from click.testing import CliRunner
import requests
from kxi.auth import Authorizer
import pytest
from kxicli import main, common
import time
from kxicli.resources import auth
from utils import get_assembly_name, return_none, test_asm_file2

ASM_NAME = get_assembly_name(test_asm_file2)
ASM_NAME2 = 'test_asm2'
@pytest.fixture
def use_default_config():
    common.config.config_file = str(Path.home() / '.insights' / 'cli-config')
    common.config.load_config("default")

@pytest.fixture
def setup_clean_slate():
    runner = CliRunner()
    result = runner.invoke(main.cli, ["auth", "login", "--serviceaccount"])
    result = runner.invoke(main.cli, ["assembly", "list"])
    assert ASM_NAME not in result.output


def mock_client_response(*args, **kwargs):
    return {'message': "abc", 'detail': {'message': "another"}}

@pytest.mark.integration
def test_basic_assembly(setup_clean_slate, use_default_config, k8s):
    runner = CliRunner()
    result = runner.invoke(main.cli, ["auth", "login", "--serviceaccount"])
    result = runner.invoke(main.cli, ["assembly", "list"])

    # Check embedded assemblies in the list
    assert result.exit_code == 0
    check_assembly_list_output(['dfx-assembly', 'iot-assembly'], [ASM_NAME], result.output)

    # Deploy basic assembly
    result = runner.invoke(main.cli, ["assembly", "deploy", "--filepath", test_asm_file2])
    time.sleep(5)
    assert result.exit_code == 0

    # Check basic assembly is running
    result = runner.invoke(main.cli, ["assembly", "list"])
    check_assembly_list_output(['dfx-assembly', 'iot-assembly', ASM_NAME], None, result.output)

    # Statuscheck
    result = runner.invoke(main.cli, ["assembly", "status", "--name", ASM_NAME])
    assert result.exit_code == 0
    json_start = result.output.index('{')
    json_str = result.output[json_start:]
    res = json.loads(json_str)

    assert True ==  res['running']

    # Teardown assembly
    result = runner.invoke(main.cli, ["assembly", "teardown", "--name", ASM_NAME, "--force"])
    time.sleep(5)
    assert result.exit_code == 0

    result = runner.invoke(main.cli, ["assembly", "list"])
    check_assembly_list_output(['dfx-assembly', 'iot-assembly'], [ASM_NAME], result.output)

def check_assembly_list_output(includes: Optional[list[str]], excludes: Optional[list[str]], output: str):
    # check all includes in the output
    if includes is not None:
        assert all(elem in output for elem in includes)

    # check excluded from output
    if excludes is not None:
        assert all(elem not in output for elem in excludes)
