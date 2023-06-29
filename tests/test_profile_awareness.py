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
        
def test_non_existent_command_throws_exception():
    commands = ["UNKNOWNCOMMAND"]
    for cmd in commands:
        run_command_with_profile(cmd, DeploymentType.ENTERPRISE)
        run_command_with_profile(cmd, DeploymentType.MICROSERVICES)        
        
        
def run_command_with_profile(cmd_name, deployment_type):
    if deployment_type == DeploymentType.MICROSERVICES:
        kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config-microservices')

    result = TEST_CLI.invoke(kxicli.main.cli, [cmd_name])

    assert result.exit_code == 2
    assert f"Error: No such command '{cmd_name}'." in result.output

    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')    


def test_default_profile():
    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config-multi')

    result = TEST_CLI.invoke(kxicli.main.cli, ["query"])
    
    cfg = kxicli.main.cli_group.config.config
    assert cfg.default_section == "default"
    assert cfg.get(cfg.default_section, "usage") == "enterprise"
    assert cfg.get(cfg.default_section, "hostname") == "https://test.kx.com"
    assert cfg.get(cfg.default_section, "namespace") == "test"
    assert cfg.get(cfg.default_section, "client.id") == "client"
    assert cfg.get(cfg.default_section, "client.secret") == "secret"

    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')


def test_non_default_profile_enterprise():
    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config-multi')

    result = TEST_CLI.invoke(kxicli.main.cli, ["--profile", "enterprise_profile", "query"])
    
    cfg = kxicli.main.cli_group.config.config
    assert cfg.default_section == "enterprise_profile"    
    assert cfg.get(cfg.default_section, "usage") == "enterprise"
    assert cfg.get(cfg.default_section, "hostname") == "https://test2.kx.com"
    assert cfg.get(cfg.default_section, "namespace") == "test2"
    assert cfg.get(cfg.default_section, "client.id") == "client2"
    assert cfg.get(cfg.default_section, "client.secret") == "secret2"
    
def test_non_default_profile_enterprise_no_default():
    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config-multi-no-default')

    result = TEST_CLI.invoke(kxicli.main.cli, ["--profile", "enterprise_profile", "query"])
    
    cfg = kxicli.main.cli_group.config.config
    assert cfg.default_section == "enterprise_profile"        
    assert cfg.get(cfg.default_section, "usage") == "enterprise"
    assert cfg.get(cfg.default_section, "hostname") == "https://test2.kx.com"
    assert cfg.get(cfg.default_section, "namespace") == "test2"
    assert cfg.get(cfg.default_section, "client.id") == "client2"
    assert cfg.get(cfg.default_section, "client.secret") == "secret2"          

    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')


def test_non_default_profile_microservices():
    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config-multi')

    result = TEST_CLI.invoke(kxicli.main.cli, ["--profile", "microservices_profile", "query"])
    
    cfg = kxicli.main.cli_group.config.config
    assert cfg.default_section == "microservices_profile"
    assert cfg.get(cfg.default_section, "usage") == "microservices"
    assert cfg.get(cfg.default_section, "hostname") == "https://test3.kx.com"
    assert cfg.get(cfg.default_section, "tp_port") == "5010"

    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')

def test_non_default_profile_microservices_no_default():
    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config-multi-no-default')

    result = TEST_CLI.invoke(kxicli.main.cli, ["--profile", "microservices_profile", "query"])
    
    cfg = kxicli.main.cli_group.config.config
    assert cfg.default_section == "microservices_profile"
    assert cfg.get(cfg.default_section, "usage") == "microservices"
    assert cfg.get(cfg.default_section, "hostname") == "https://test3.kx.com"
    assert cfg.get(cfg.default_section, "tp_port") == "5010"

    kxicli.main.cli_group.config.config_file = str(Path(__file__).parent / 'files' / 'test-cli-config')
