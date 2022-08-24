from dataclasses import dataclass
import dataclasses
from typing import List, Optional
from msgraph.core import GraphClient
from dataclasses_json import LetterCase, config, dataclass_json

import json


@dataclass_json(letter_case=LetterCase.CAMEL)
@dataclass
class Web:
    home_page_url: Optional[str]
    logout_url: Optional[str]
    redirect_uris: List[str]


@dataclass_json(letter_case=LetterCase.CAMEL)
@dataclass
class AppRegistration:
    id: str
    app_id: str
    display_name: str
    group_membership_claims: Optional[str]
    web: Web


@dataclass_json(letter_case=LetterCase.CAMEL)
@dataclass
class Group:
    id: str
    display_name: str


class AzureADClient:

    def __init__(self, credential):
        self.graph_client = GraphClient(credential=credential)

    def get_azure_app_registration_by_name(self,
                                           azure_app_registration_name: str
                                           ) -> AppRegistration:
        headers = {"consistencyLevel": "eventual"}
        res = self.graph_client.get(f"/applications?$filter=displayName eq '{azure_app_registration_name}'&$count=true",
                                    headers=headers)

        res.raise_for_status()
        data = res.json()

        return None if data["@odata.count"] == 0 else AppRegistration.from_dict(data["value"][0])

    def get_app_registrations(self
                              ) -> List[AppRegistration]:
        headers = {"consistencyLevel": "eventual"}
        res = self.graph_client.get("/applications", headers=headers)

        res.raise_for_status()
        return [AppRegistration.from_dict(x) for x in res.json()["value"]]

    def patch_app_registration(self,
                               app_registration: AppRegistration
                               ) -> AppRegistration:  # pragma: no cover
        headers = {"content-type": "application/json"}

        res = self.graph_client.patch(
            f"/applications/{app_registration.id}", app_registration.to_json(), headers=headers)
        res.raise_for_status()
        return app_registration

    def add_secret_to_app_registration(self,
                                       app_registration: AppRegistration,
                                       secret_display_name: str
                                       ) -> str:  # pragma: no cover
        headers = {"content-type": "application/json"}

        body = {
            "passwordCredential": {"displayName": secret_display_name}
        }

        res = self.graph_client.post(
            f"/applications/{app_registration.id}/addPassword", json.dumps(body), headers=headers)

        res.raise_for_status()
        data = res.json()

        return data["secretText"]

    def get_azure_ad_group_by_name(self,
                                   azure_group_name: str
                                   ) -> Group:
        headers = {"consistencyLevel": "eventual"}
        res = self.graph_client.get(f"/groups?$filter=displayName eq '{azure_group_name}'&$count=true",
                                    headers=headers)

        res.raise_for_status()
        data = res.json()

        return None if data["@odata.count"] == 0 else Group.from_dict(data["value"][0])
