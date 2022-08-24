import json
import os
import requests_mock
import pytest
from pytest_mock import MockerFixture
from unittest import mock
from kxicli.azure_ad import AppRegistration, Group, Web, AzureADClient
from azure.identity import ClientSecretCredential

script_dir = os.path.dirname(__file__)

application_response = os.path.join(
    script_dir, "files/azure-ad-applications.json")

application_empty_response = os.path.join(
    script_dir, "files/azure-ad-applications-empty.json")

group_response = os.path.join(
    script_dir, "files/azure-ad-group.json")

group_empty_response = os.path.join(
    script_dir, "files/azure-ad-group-empty.json")


credential = ClientSecretCredential("test", "test", "test")

expected_app_registration = AppRegistration(
    id="id",
    app_id="appId",
    display_name="test-app",
    group_membership_claims="SecurityGroup",
    web=Web(
        home_page_url=None,
        logout_url=None,
        redirect_uris=["http://fake-redirect.com"]
    )
)

expected_group = Group(id="id", display_name="groupname")


def test_get_azure_app_registration_by_name__returns_expected_app_registration():

    app_registration_name = "test"
    fake_url = f"https://graph.microsoft.com/v1.0/applications?$filter=displayName eq '{app_registration_name}'&$count=true"

    ad_client = AzureADClient(credential)

    with requests_mock.Mocker() as m, open(application_response, "r") as my_file:
        m.get(fake_url, text=my_file.read())

        assert ad_client.get_azure_app_registration_by_name(
            app_registration_name) == expected_app_registration


def test_get_azure_app_registration_by_name__returns_none():

    app_registration_name = "test"
    fake_url = f"https://graph.microsoft.com/v1.0/applications?$filter=displayName eq '{app_registration_name}'&$count=true"

    ad_client = AzureADClient(credential)

    with requests_mock.Mocker() as m, open(application_empty_response, "r") as my_file:
        m.get(fake_url, text=my_file.read())

        assert ad_client.get_azure_app_registration_by_name(
            app_registration_name) == None


def test_get_azure_app_registrations__returns_list():

    fake_url = f"https://graph.microsoft.com/v1.0/applications"

    ad_client = AzureADClient(credential)

    with requests_mock.Mocker() as m, open(application_response, "r") as my_file:
        m.get(fake_url, text=my_file.read())

        assert ad_client.get_app_registrations() == [expected_app_registration]


def test_get_azure_ad_group_by_name():

    azure_group_name = "groupname"
    fake_url = f"https://graph.microsoft.com/v1.0/groups?$filter=displayName eq '{azure_group_name}'&$count=true"

    ad_client = AzureADClient(credential)

    with requests_mock.Mocker() as m, open(group_response, "r") as my_file:
        m.get(fake_url, text=my_file.read())

        assert ad_client.get_azure_ad_group_by_name(
            azure_group_name) == expected_group


def test_get_azure_ad_group_by_name():

    azure_group_name = "groupname"
    fake_url = f"https://graph.microsoft.com/v1.0/groups?$filter=displayName eq '{azure_group_name}'&$count=true"

    ad_client = AzureADClient(credential)

    with requests_mock.Mocker() as m, open(group_empty_response, "r") as my_file:
        m.get(fake_url, text=my_file.read())

        assert ad_client.get_azure_ad_group_by_name(
            azure_group_name) == None
