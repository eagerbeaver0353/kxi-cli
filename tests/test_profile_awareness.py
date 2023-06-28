import pytest
import importlib
import json
import sys
from unittest.mock import ANY, call, MagicMock, patch
from pathlib import Path
from pytest_mock import MockerFixture
from click.testing import CliRunner
from kxi import DeploymentType
import kxicli.main

TEST_CLI = CliRunner()

def test_enterprise_commands_throw_exception_with_microservices_profile():
    commands = ["assembly","auth","backup","client","install","package","user"]
    for cmd in commands:
        run_command_with_profile(cmd, DeploymentType.MICROSERVICES)
        
def test_microservices_commands_throw_exception_with_microservices_profile():
    commands = ["publish"]
    for cmd in commands:
        run_command_with_profile(cmd, DeploymentType.ENTERPRISE)
        
        

def run_command_with_profile(cmd_name, deployment_type):
    if deployment_type == DeploymentType.MICROSERVICES:
        kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config-microservices')

        result = TEST_CLI.invoke(kxicli.main.cli, [cmd_name])

        assert result.exit_code == 2
        assert f"Error: No such command '{cmd_name}'." in result.output

        kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')    
