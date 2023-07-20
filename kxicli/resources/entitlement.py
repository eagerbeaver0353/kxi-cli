from __future__ import annotations

from enum import auto
from typing import Any, List, Optional
from uuid import UUID

import pydantic
from pydantic import BaseModel

from kxi.rest import ApiClient, DataFormat, _wrap_request
from kxi.util import AutoNameEnum


class EntityType(AutoNameEnum):
    """Entity types for api."""

    assembly = auto()
    package = auto()
    view = auto()
    query = auto()
    all = ""


class Entitlement(BaseModel, extra="allow"):
    """Entitlement model."""

    id: UUID
    entity: str
    entityType: EntityType
    owner: UUID
    groups: List[UUID]


class Actor(BaseModel, extra="allow"):
    """Actor model."""

    id: UUID
    name: str
    path: str


class EntitlementService(ApiClient):
    """User manager api class."""

    service_path = "/entitlements"
    data_format = DataFormat.JSON

    def create(
        self,
        id: UUID,
        entity: str,
        entityType: EntityType,
        owner: UUID | None = None,
        groups: List[UUID] | None = None,
    ):
        """Create an entity."""
        data = {
            "id": str(id),
            "entity": entity,
            "entityType": entityType,
        }

        if owner is not None:
            data["owner"] = str(owner)

        if groups is not None and groups != []:
            data["groups"] = [str(g) for g in groups]

        return self._post("/v1/entities", json=data)

    def list(self, **kwargs) -> List[Entitlement]:
        """List entities."""
        return pydantic.parse_obj_as(List[Entitlement], self._get("/v1/entities", **kwargs))

    def get(self, id: str, **kwargs) -> Entitlement:
        """Get an entity by ID."""
        return pydantic.parse_obj_as(Entitlement, self._get(f"/v1/entities/{id}", **kwargs))

    def update(
        self,
        id: UUID,
        entity: str | None = None,
        owner: UUID | None = None,
        groups: List[UUID] | None = None,
    ):
        """Update an entity by ID."""
        data = {}

        if entity is not None:
            data["entity"] = entity

        if owner is not None:
            data["owner"] = str(owner)

        if groups is not None and groups != []:
            data["groups"] = [str(g) for g in groups]

        return self._patch(f"/v1/entities/{id}", json=data)

    def delete(self, id: str, **kwargs) -> Entitlement:
        """Delete an entity by ID."""
        return self._delete(f"/v1/entities/{id}", **kwargs)

    def actors(self, **kwargs) -> List[Actor]:
        """Get actors."""
        return pydantic.parse_obj_as(List[Actor], self._get("/v1/actors", **kwargs))

    # Temp hotfix because patch isn't available on ApiClient
    @_wrap_request
    def _patch(self, url: str, **kwargs) -> Any:
        return self._session.patch(url, **kwargs)
