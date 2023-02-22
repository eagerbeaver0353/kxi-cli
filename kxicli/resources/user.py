from __future__ import annotations

from kxi.auth import Authorizer
from kxicli import phrases

class UserNotFoundException(Exception):
    pass

class RoleNotFoundException(Exception):
    pass

class MultipleUsersWithNameException(Exception):
    pass

class UserManager():
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        user_realm: str = "insights",
        timeout: int = 2

    ):
        self.host = host
        self.auth = Authorizer.for_admin(host, username=username, password=password, timeout=timeout)
        self.url = f"{self.host}/auth/admin/realms/{user_realm}"

    def create_user(
        self,
        username: str,
        password: str,
        email: str | None = None,
        enabled: bool = True,
        temporary: bool = True,
    ):
        data = {
            "username": username,
            "enabled": enabled,
            "email": email,
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": temporary
                }
            ]
        }

        self.auth.session.post(f"{self.url}/users", json=data).raise_for_status()

    def list_users(self, **kwargs):
        res = self.auth.session.get(f"{self.url}/users", **kwargs)
        res.raise_for_status()
        users = res.json()
        return users

    def get_user_by_name(self, username: str):
        query = {
            "username": username,
            "exact": "true"
        }
        user = self.list_users(params=query)
        if len(user) == 0:
            raise UserNotFoundException(username)
        elif len(user) > 1:
            raise MultipleUsersWithNameException(username)
        return user[0]

    def delete_user(self, username):
        user_id = self.get_user_by_name(username)["id"]
        return self.auth.session.delete(f"{self.url}/users/{user_id}").raise_for_status()

    def get_role_data(self, roles):
        available = self.get_roles()

        data = [role for role in available if role['name'] in roles]

        if len(data) != len(roles):
            missing_roles = [role for role in roles if role not in [x['name'] for x in data]]
            raise RoleNotFoundException(missing_roles)

        return data

    def assign_roles(self, username: str, roles: list[str]):
        user_id = self.get_user_by_name(username)["id"]
        return self.auth.session.post(f"{self.url}/users/{user_id}/role-mappings/realm", json=self.get_role_data(roles))

    def remove_roles(self, username: str, roles: list[str]):
        user_id = self.get_user_by_name(username)["id"]
        return self.auth.session.delete(f"{self.url}/users/{user_id}/role-mappings/realm", json=self.get_role_data(roles))

    def get_roles(self):
        res = self.auth.session.get(f"{self.url}/roles")
        res.raise_for_status()
        return res.json()

    def get_roles_for_user(self, username: str, role_type: str):
        user_id = self.get_user_by_name(username)["id"]

        endpoint = f"{self.url}/users/{user_id}/role-mappings/realm"
        if role_type in ["available", "composite"]:
            endpoint = f"{endpoint}/{role_type}"

        res = self.auth.session.get(endpoint)
        res.raise_for_status()
        return res.json()

    def get_assigned_roles(self, username):
        return self.get_roles_for_user(username, "")

    def get_effective_roles(self, username):
        return self.get_roles_for_user(username, "composite")

    def reset_password(
        self,
        username: str,
        password: str,
        temporary: bool = True,
    ):
        user_id = self.get_user_by_name(username)["id"]
        data = {
            "type": "password",
            "value": password,
            "temporary": temporary
        }
        self.auth.session.put(f"{self.url}/users/{user_id}/reset-password", json=data).raise_for_status()
