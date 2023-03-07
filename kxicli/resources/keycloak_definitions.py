from tabulate import tabulate

def format_idp_list(idps) -> str:
    selection = [(x["alias"], x["displayName"], x["config"]["clientId"])
                 for x in idps]
    return tabulate(selection, headers=["Alias", "DisplayName", "Azure App Registration Application ID"])


def format_mapper_list(existing_mappers):
    return tabulate([[x] for x in existing_mappers], headers=["Mapper"])


# https://www.keycloak.org/docs-api/18.0/rest-api/#_identityproviderrepresentation
def get_idp_definition(
    alias: str,
    display_name: str,
    client_id: str,
    client_secret: str,
    azure_tenant_id: str
):
    return {
        "alias": f"{alias}",
        "displayName": f"{display_name}",
        "providerId": "oidc",
        "enabled": "true",
        "updateProfileFirstLoginMode": "on",
        "trustEmail": "true",
        "storeToken": "false",
        "addReadTokenRoleOnCreate": "false",
        "authenticateByDefault": "false",
        "linkOnly": "false",
        "firstBrokerLoginFlowAlias": "first broker login",
        "config": {
            "clientId": f"{client_id}",
            "tokenUrl": f"https://login.microsoftonline.com/{azure_tenant_id}/oauth2/v2.0/token",
            "authorizationUrl": f"https://login.microsoftonline.com/{azure_tenant_id}/oauth2/v2.0/authorize",
            "clientAuthMethod": "client_secret_post",
            "syncMode": "FORCE",
            "clientSecret": f"{client_secret}",
            "defaultScope": "openid profile email",
            "useJwksUrl": "true"
        }
    }


# https://www.keycloak.org/docs-api/18.0/rest-api/#_identityprovidermapperrepresentation
def get_preferred_username_mapper_definition(
        idp_alias: str):
    return {
        "name": "Preferred Username",
        "identityProviderAlias": f"{idp_alias}",
        "identityProviderMapper": "oidc-username-idp-mapper",
        "config": {
            "template": "${CLAIM.preferred_username | localpart}",
            "syncMode": "INHERIT",
            "target": "LOCAL"
        }
    }


# https://www.keycloak.org/docs-api/18.0/rest-api/#_identityprovidermapperrepresentation
def get_email_mapper_definition(
        idp_alias: str):
    return {
        "name": "Email",
        "identityProviderAlias": f"{idp_alias}",
        "identityProviderMapper": "oidc-user-attribute-idp-mapper",
        "config": {
            "syncMode": "INHERIT",
            "claim": "preferred_username",
            "user.attribute": "email"
        }
    }


# https://www.keycloak.org/docs-api/15.0/rest-api/#_identityprovidermapperrepresentation
def get_role_mapper_definition(mapper_name: str,
                               idp_alias: str,
                               role: str,
                               azure_ad_group: str
                               ):
    return {
        "name": f"{mapper_name}",
        "identityProviderAlias": f"{idp_alias}",
        "identityProviderMapper": "oidc-role-idp-mapper",
        "config": {
            "syncMode": "INHERIT",
            "claim": "groups",
            "role": f"{role}",
            "claim.value": f"{azure_ad_group}"
        }
    }