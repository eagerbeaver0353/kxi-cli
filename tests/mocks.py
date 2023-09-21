from unittest.mock import MagicMock

import requests


def mock_assembly_list(k8s: MagicMock, response=()):
    k8s.assemblies.get.side_effect = lambda *args, **kwargs: response
    return k8s.assemblies


def http_response(url, **kwargs):
    """
    Generic HTTP response
    """
    response = requests.Response()
    response.status_code = kwargs.get("status_code", 200)
    response._content = kwargs.get("content", b"{}")
    response.headers["content-type"] = "application/json"
    if 200 <= response.status_code < 300:
        return response
    else:
        raise requests.exceptions.HTTPError(response=response)
